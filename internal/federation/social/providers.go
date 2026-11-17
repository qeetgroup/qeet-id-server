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

// A provider's secret is stored encrypted and never returned, and every change
// is audited with the fields it changed (never the secret). A switched-off
// provider looks to an unauthenticated caller exactly like one never set up.
// Removing a provider keeps the identities linked through it.

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

func (s *Service) recordProviderChange(ctx context.Context, tx pgx.Tx, by ChangedBy, organizationID, providerID uuid.UUID, action string, meta map[string]any) error {
	tid, pid := organizationID, providerID
	actorType := by.ActorType
	if actorType == "" {
		actorType = "system"
	}
	return audit.Record(ctx, tx, audit.Event{
		OrganizationID: &tid,
		ActorUserID:    by.UserID,
		ActorType:      actorType,
		Action:         action,
		ResourceType:   "social_provider",
		ResourceID:     &pid,
		IP:             by.IP,
		UserAgent:      by.UserAgent,
		RequestID:      by.RequestID,
		Metadata:       meta,
	})
}

// sealSecret encrypts a provider secret for storage.
func (s *Service) sealSecret(organizationID uuid.UUID, provider, secret string) (ciphertext, nonce []byte, err error) {
	if s.box == nil {
		return nil, nil, errs.ErrInternalServer.WithDetail("social provider secret encryption is unavailable")
	}
	return s.box.Seal(organizationID, "social-provider", provider, []byte(secret))
}

// UpdateProviderInput changes some of a provider's settings; a field left nil
// is kept. An empty ClientSecret also keeps the stored one.
type UpdateProviderInput struct {
	ClientID     *string `json:"client_id"`
	ClientSecret *string `json:"client_secret"`
	DiscoveryURL *string `json:"discovery_url"`
	AppleTeamID  *string `json:"apple_team_id"`
	AppleKeyID   *string `json:"apple_key_id"`
	Enabled      *bool   `json:"enabled"`
}

// UpdateProvider changes the given fields of the organization's provider and
// returns it. ErrNotFound when the organization has no such provider —
// including one that belongs to another organization. Switching it off is
// refused with ErrSocialProviderInUse, as deleting it is, while anyone can
// sign in only through it.
func (s *Service) UpdateProvider(ctx context.Context, organizationID uuid.UUID, provider string, in UpdateProviderInput, by ChangedBy) (*Provider, error) {
	var bad []errs.FieldError
	if in.ClientID != nil && strings.TrimSpace(*in.ClientID) == "" {
		bad = append(bad, errs.FieldError{Field: "client_id", Code: "required", Message: "Enter the client ID."})
	}
	kind := adapterKind(provider)
	if kind != kindOIDC {
		in.DiscoveryURL = nil
	}
	if kind != kindApple {
		in.AppleTeamID, in.AppleKeyID = nil, nil
	}
	if in.DiscoveryURL != nil && *in.DiscoveryURL != "" {
		if _, err := s.egress.ValidateHTTPURL(*in.DiscoveryURL); err != nil {
			bad = append(bad, errs.FieldError{Field: "discovery_url", Code: "invalid", Message: "Enter a public https discovery URL."})
		}
	}
	for _, f := range []struct {
		name string
		v    *string
	}{{"apple_team_id", in.AppleTeamID}, {"apple_key_id", in.AppleKeyID}} {
		if f.v != nil && strings.TrimSpace(*f.v) == "" {
			bad = append(bad, errs.FieldError{Field: f.name, Code: "required", Message: "Enter Apple's team ID and key ID."})
		}
	}
	if len(bad) > 0 {
		return nil, errs.ErrValidationFailed.WithFields(bad)
	}
	replaceSecret := in.ClientSecret != nil && *in.ClientSecret != ""
	var ciphertext, nonce []byte
	if replaceSecret {
		var err error
		if ciphertext, nonce, err = s.sealSecret(organizationID, provider, *in.ClientSecret); err != nil {
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
	var clientID string
	var teamID, keyID *string
	if err := tx.QueryRow(ctx, `
		SELECT id, enabled, client_id, apple_team_id, apple_key_id FROM organization.social_providers
		WHERE organization_id = $1 AND provider = $2 FOR UPDATE`, organizationID, provider).Scan(&id, &wasEnabled, &clientID, &teamID, &keyID); errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	} else if err != nil {
		return nil, err
	}
	// A new Apple key must sign with the team and key ids it will be used with.
	if kind == kindApple && replaceSecret {
		pick := func(given, stored *string) string {
			if given != nil {
				return *given
			}
			if stored != nil {
				return *stored
			}
			return ""
		}
		if in.ClientID != nil {
			clientID = *in.ClientID
		}
		if err := checkAppleKey(clientID, pick(in.AppleTeamID, teamID), pick(in.AppleKeyID, keyID), *in.ClientSecret); err != nil {
			return nil, err
		}
	}
	if wasEnabled && in.Enabled != nil && !*in.Enabled {
		dependent, _, err := providerDependents(ctx, tx, organizationID, provider)
		if err != nil {
			return nil, err
		}
		if dependent > 0 {
			return nil, errs.ErrSocialProviderInUse.WithMetadata(map[string]any{"people": dependent})
		}
	}
	var p Provider
	if err := tx.QueryRow(ctx, `
		UPDATE organization.social_providers SET
		    client_id = COALESCE($2, client_id),
		    discovery_url = CASE WHEN $3::boolean THEN NULLIF($4, '') ELSE discovery_url END,
		    enabled = COALESCE($5, enabled),
		    client_secret_ct = CASE WHEN $6::boolean THEN $7 ELSE client_secret_ct END,
		    client_secret_nonce = CASE WHEN $6::boolean THEN $8 ELSE client_secret_nonce END,
		    apple_team_id = COALESCE($9, apple_team_id),
		    apple_key_id = COALESCE($10, apple_key_id)
		WHERE id = $1
		RETURNING id, organization_id, provider, client_id, discovery_url, enabled, created_at, apple_team_id, apple_key_id`,
		id, in.ClientID, in.DiscoveryURL != nil, in.DiscoveryURL, in.Enabled, replaceSecret, ciphertext, nonce, in.AppleTeamID, in.AppleKeyID).
		Scan(&p.ID, &p.OrganizationID, &p.Provider, &p.ClientID, &p.DiscoveryURL, &p.Enabled, &p.CreatedAt, &p.AppleTeamID, &p.AppleKeyID); err != nil {
		return nil, err
	}
	p.Kind = kind

	var changed []string
	if in.ClientID != nil {
		changed = append(changed, "client_id")
	}
	if in.DiscoveryURL != nil {
		changed = append(changed, "discovery_url")
	}
	if in.AppleTeamID != nil {
		changed = append(changed, "apple_team_id")
	}
	if in.AppleKeyID != nil {
		changed = append(changed, "apple_key_id")
	}
	if replaceSecret {
		changed = append(changed, "client_secret")
	}
	if len(changed) > 0 {
		if err := s.recordProviderChange(ctx, tx, by, organizationID, id, "social_provider.updated", map[string]any{
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
		if err := s.recordProviderChange(ctx, tx, by, organizationID, id, action, map[string]any{"provider": provider}); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &p, nil
}

// DeleteProvider removes the organization's provider. Refused with
// ErrSocialProviderInUse while anyone in the organization can sign in only
// through it, and with ErrNotFound when the organization has no such provider.
func (s *Service) DeleteProvider(ctx context.Context, organizationID uuid.UUID, provider string, by ChangedBy) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var id uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT id FROM organization.social_providers
		WHERE organization_id = $1 AND provider = $2 FOR UPDATE`, organizationID, provider).Scan(&id); errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound
	} else if err != nil {
		return err
	}
	dependent, linked, err := providerDependents(ctx, tx, organizationID, provider)
	if err != nil {
		return err
	}
	if dependent > 0 {
		return errs.ErrSocialProviderInUse.WithMetadata(map[string]any{"people": dependent})
	}
	if _, err := tx.Exec(ctx, `DELETE FROM organization.social_providers WHERE id = $1`, id); err != nil {
		return err
	}
	if err := s.recordProviderChange(ctx, tx, by, organizationID, id, "social_provider.deleted", map[string]any{
		"provider": provider, "linked_identities_kept": linked,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// providerDependents counts, on tx, the people who can sign in to the
// organization only through provider, and every identity linked to it.
func providerDependents(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, provider string) (dependent, linked int64, err error) {
	err = tx.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE
		           NOT EXISTS (SELECT 1 FROM auth.password_credentials pc WHERE pc.user_id = ei.user_id)
		       AND NOT EXISTS (SELECT 1 FROM auth.passkey_credentials pk WHERE pk.user_id = ei.user_id)
		       AND NOT EXISTS (SELECT 1 FROM account.external_identities other
		                       WHERE other.user_id = ei.user_id AND other.id <> ei.id
		                         AND NOT (other.organization_id = ei.organization_id AND other.provider = ei.provider))
		       AND NOT EXISTS (SELECT 1 FROM auth.platform_social_identities ps WHERE ps.user_id = ei.user_id)),
		       count(*)
		FROM account.external_identities ei
		JOIN account.users u ON u.id = ei.user_id AND u.deleted_at IS NULL
		WHERE ei.organization_id = $1 AND ei.provider = $2`, organizationID, provider).Scan(&dependent, &linked)
	return dependent, linked, err
}

func (h *Handler) updateProvider(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in UpdateProviderInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.DiscoveryURL != nil {
		if err := h.checkTrust(r, organizationID, chi.URLParam(r, "provider"), *in.DiscoveryURL); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
	p, err := h.Service.UpdateProvider(r.Context(), organizationID, chi.URLParam(r, "provider"), in, changedBy(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

func (h *Handler) deleteProvider(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.DeleteProvider(r.Context(), organizationID, chi.URLParam(r, "provider"), changedBy(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
