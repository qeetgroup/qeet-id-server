package social

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// An organisation's social providers are managed for their whole life: added
// (or replaced) with UpsertProvider, changed field by field — switched off or
// on, a secret replaced — with UpdateProvider, and removed with DeleteProvider.
// A secret is stored encrypted and never returned. A provider switched off
// stays off whatever else is saved, and is no longer offered or usable for
// sign-in; to an unauthenticated caller it reads exactly like a provider that
// was never set up. Every change is audited, naming the fields changed; the
// secret's value never is.
//
// Removing a provider keeps the identities people linked through it: they
// still appear in those people's connected accounts and work again if the
// provider is added back. Removal is refused while anyone in the organisation
// can sign in only through that provider (no password, no passkey, no other
// linked identity); switch it off instead, or give them another way in first.

// ChangedBy is who changed a provider, for the audit record.
type ChangedBy struct {
	UserID    *uuid.UUID
	ActorType string
	IP        string
	UserAgent string
	RequestID string
}

func changedBy(r *http.Request) ChangedBy {
	c := ChangedBy{ActorType: "user", IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)}
	if p := httpx.PrincipalFromCtx(r.Context()); p != nil {
		c.UserID = p.UserID
		if p.ActorType != "" {
			c.ActorType = p.ActorType
		}
	}
	return c
}

func (s *Service) recordProviderChange(ctx context.Context, tx pgx.Tx, by ChangedBy, tenantID, providerID uuid.UUID, action string, meta map[string]any) error {
	tid, pid := tenantID, providerID
	actorType := by.ActorType
	if actorType == "" {
		actorType = "system"
	}
	return audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  by.UserID,
		ActorType:    actorType,
		Action:       action,
		ResourceType: "social_provider",
		ResourceID:   &pid,
		IP:           by.IP,
		UserAgent:    by.UserAgent,
		RequestID:    by.RequestID,
		Metadata:     meta,
	})
}

// sealSecret encrypts a provider secret for storage.
func (s *Service) sealSecret(tenantID uuid.UUID, provider, secret string) (ciphertext, nonce []byte, err error) {
	if s.box == nil {
		return nil, nil, errs.ErrInternalServer.WithDetail("social provider secret encryption is unavailable")
	}
	return s.box.Seal(tenantID, "social-provider", provider, []byte(secret))
}

// UpdateProviderInput changes some of a provider's settings; a field left nil
// is kept. An empty ClientSecret also keeps the stored one.
type UpdateProviderInput struct {
	ClientID     *string `json:"client_id"`
	ClientSecret *string `json:"client_secret"`
	DiscoveryURL *string `json:"discovery_url"`
	Enabled      *bool   `json:"enabled"`
}

// UpdateProvider changes the given fields of the organisation's provider and
// returns it. ErrNotFound when the organisation has no such provider —
// including one that belongs to another organisation.
func (s *Service) UpdateProvider(ctx context.Context, tenantID uuid.UUID, provider string, in UpdateProviderInput, by ChangedBy) (*Provider, error) {
	var bad []errs.FieldError
	if in.ClientID != nil && strings.TrimSpace(*in.ClientID) == "" {
		bad = append(bad, errs.FieldError{Field: "client_id", Code: "required", Message: "Enter the client ID."})
	}
	if in.DiscoveryURL != nil && *in.DiscoveryURL != "" {
		if _, err := s.egress.ValidateHTTPURL(*in.DiscoveryURL); err != nil {
			bad = append(bad, errs.FieldError{Field: "discovery_url", Code: "invalid", Message: "Enter a public https discovery URL."})
		}
	}
	if len(bad) > 0 {
		return nil, errs.ErrValidationFailed.WithFields(bad)
	}
	replaceSecret := in.ClientSecret != nil && *in.ClientSecret != ""
	var ciphertext, nonce []byte
	if replaceSecret {
		var err error
		if ciphertext, nonce, err = s.sealSecret(tenantID, provider, *in.ClientSecret); err != nil {
			return nil, err
		}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var wasEnabled bool
	var id uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT id, enabled FROM tenant.social_providers
		WHERE tenant_id = $1 AND provider = $2 FOR UPDATE`, tenantID, provider).Scan(&id, &wasEnabled); errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	} else if err != nil {
		return nil, err
	}
	var p Provider
	if err := tx.QueryRow(ctx, `
		UPDATE tenant.social_providers SET
		    client_id = COALESCE($2, client_id),
		    discovery_url = CASE WHEN $3::boolean THEN NULLIF($4, '') ELSE discovery_url END,
		    enabled = COALESCE($5, enabled),
		    client_secret = CASE WHEN $6::boolean THEN '' ELSE client_secret END,
		    client_secret_ct = CASE WHEN $6::boolean THEN $7 ELSE client_secret_ct END,
		    client_secret_nonce = CASE WHEN $6::boolean THEN $8 ELSE client_secret_nonce END,
		    encryption_version = CASE WHEN $6::boolean THEN 1 ELSE encryption_version END
		WHERE id = $1
		RETURNING id, tenant_id, provider, client_id, discovery_url, enabled, created_at`,
		id, in.ClientID, in.DiscoveryURL != nil, in.DiscoveryURL, in.Enabled, replaceSecret, ciphertext, nonce).
		Scan(&p.ID, &p.TenantID, &p.Provider, &p.ClientID, &p.DiscoveryURL, &p.Enabled, &p.CreatedAt); err != nil {
		return nil, err
	}

	var changed []string
	if in.ClientID != nil {
		changed = append(changed, "client_id")
	}
	if in.DiscoveryURL != nil {
		changed = append(changed, "discovery_url")
	}
	if replaceSecret {
		changed = append(changed, "client_secret")
	}
	if len(changed) > 0 {
		if err := s.recordProviderChange(ctx, tx, by, tenantID, id, "social_provider.updated", map[string]any{
			"provider": provider, "fields": changed, "secret_replaced": replaceSecret,
		}); err != nil {
			return nil, err
		}
	}
	if p.Enabled != wasEnabled {
		action := "social_provider.disabled"
		if p.Enabled {
			action = "social_provider.enabled"
		}
		if err := s.recordProviderChange(ctx, tx, by, tenantID, id, action, map[string]any{"provider": provider}); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &p, nil
}

// DeleteProvider removes the organisation's provider. Refused with
// ErrSocialProviderInUse while anyone in the organisation can sign in only
// through it, and with ErrNotFound when the organisation has no such provider.
func (s *Service) DeleteProvider(ctx context.Context, tenantID uuid.UUID, provider string, by ChangedBy) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var id uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT id FROM tenant.social_providers
		WHERE tenant_id = $1 AND provider = $2 FOR UPDATE`, tenantID, provider).Scan(&id); errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound
	} else if err != nil {
		return err
	}
	var dependent, linked int64
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE
		           NOT EXISTS (SELECT 1 FROM auth.password_credentials pc WHERE pc.user_id = ei.user_id)
		       AND NOT EXISTS (SELECT 1 FROM auth.passkey_credentials pk WHERE pk.user_id = ei.user_id)
		       AND NOT EXISTS (SELECT 1 FROM "user".external_identities other
		                       WHERE other.user_id = ei.user_id AND other.id <> ei.id
		                         AND NOT (other.tenant_id = ei.tenant_id AND other.provider = ei.provider))
		       AND NOT EXISTS (SELECT 1 FROM auth.platform_social_identities ps WHERE ps.user_id = ei.user_id)),
		       count(*)
		FROM "user".external_identities ei
		JOIN "user".users u ON u.id = ei.user_id AND u.deleted_at IS NULL
		WHERE ei.tenant_id = $1 AND ei.provider = $2`, tenantID, provider).Scan(&dependent, &linked); err != nil {
		return err
	}
	if dependent > 0 {
		return errs.ErrSocialProviderInUse.WithMetadata(map[string]any{"people": dependent})
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tenant.social_providers WHERE id = $1`, id); err != nil {
		return err
	}
	if err := s.recordProviderChange(ctx, tx, by, tenantID, id, "social_provider.deleted", map[string]any{
		"provider": provider, "linked_identities_kept": linked,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (h *Handler) updateProvider(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in UpdateProviderInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	p, err := h.Service.UpdateProvider(r.Context(), tenantID, chi.URLParam(r, "provider"), in, changedBy(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

func (h *Handler) deleteProvider(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.DeleteProvider(r.Context(), tenantID, chi.URLParam(r, "provider"), changedBy(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
