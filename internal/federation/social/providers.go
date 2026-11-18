package social

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/identitylink"
	"github.com/qeetgroup/qeet-id-server/internal/federation/social/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// A provider's secret is stored encrypted and never returned, and every change
// is audited with the fields it changed (never the secret). A switched-off
// provider looks to an unauthenticated caller exactly like one never set up.
// Removing a provider keeps the identities linked through it.

// recordProviderChange audits, in tx, by's change to organizationID's
// provider; one with no actor type is the system's.
func recordProviderChange(ctx context.Context, tx pgx.Tx, by audit.Actor, organizationID, providerID uuid.UUID, action string, meta map[string]any) error {
	if by.Type == "" {
		by.Type = "system"
	}
	return audit.Record(ctx, tx, by.Event(organizationID, action, "social_provider", providerID, meta))
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
func (s *Service) UpdateProvider(ctx context.Context, organizationID uuid.UUID, provider string, in UpdateProviderInput, by audit.Actor) (*Provider, error) {
	kind := adapterKind(provider)
	if err := s.checkProviderUpdate(kind, &in); err != nil {
		return nil, err
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
	q := s.q.WithTx(tx)
	current, err := q.LockSocialProvider(ctx, dbgen.LockSocialProviderParams{OrganizationID: organizationID, Provider: provider})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	} else if err != nil {
		return nil, err
	}
	id, wasEnabled, clientID, teamID, keyID := current.ID, current.Enabled, current.ClientID, current.AppleTeamID, current.AppleKeyID
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
		deps, err := q.SocialProviderDependents(ctx, dbgen.SocialProviderDependentsParams{OrganizationID: organizationID, Provider: provider})
		if err != nil {
			return nil, err
		}
		if deps.Dependent > 0 {
			return nil, ErrProviderInUse.WithMetadata(map[string]any{"people": deps.Dependent})
		}
	}
	r, err := q.UpdateSocialProvider(ctx, dbgen.UpdateSocialProviderParams{
		ID: id, OrganizationID: organizationID, ClientID: in.ClientID,
		SetDiscoveryUrl: in.DiscoveryURL != nil, DiscoveryUrl: in.DiscoveryURL, Enabled: in.Enabled,
		ReplaceSecret: replaceSecret, ClientSecretCt: ciphertext, ClientSecretNonce: nonce,
		AppleTeamID: in.AppleTeamID, AppleKeyID: in.AppleKeyID,
	})
	if err != nil {
		return nil, err
	}
	p := Provider{
		ID: r.ID, OrganizationID: r.OrganizationID, Provider: r.Provider, Kind: kind, ClientID: r.ClientID,
		DiscoveryURL: r.DiscoveryUrl, Enabled: r.Enabled, CreatedAt: r.CreatedAt, AppleTeamID: r.AppleTeamID, AppleKeyID: r.AppleKeyID,
	}
	if err := recordProviderUpdate(ctx, tx, by, organizationID, id, provider, in, replaceSecret, wasEnabled, p.Enabled); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &p, nil
}

// checkProviderUpdate refuses an update to a provider of kind that names an
// empty client ID, a discovery URL that isn't public https, or an empty Apple
// team or key ID. It drops the fields kind has no use for from in.
func (s *Service) checkProviderUpdate(kind string, in *UpdateProviderInput) error {
	var bad []errs.FieldError
	if in.ClientID != nil && strings.TrimSpace(*in.ClientID) == "" {
		bad = append(bad, errs.FieldError{Field: "client_id", Code: "required", Message: "Enter the client ID."})
	}
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
		return errs.ErrValidationFailed.WithFields(bad)
	}
	return nil
}

// recordProviderUpdate audits, in tx, by's update of organizationID's provider
// id: the fields in names (never the secret itself), and switching it on or
// off.
func recordProviderUpdate(ctx context.Context, tx pgx.Tx, by audit.Actor, organizationID, id uuid.UUID, provider string, in UpdateProviderInput, replaceSecret, wasEnabled, enabled bool) error {
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
		if err := recordProviderChange(ctx, tx, by, organizationID, id, "social_provider.updated", map[string]any{
			"provider": provider, "fields": changed, "secret_replaced": replaceSecret,
		}); err != nil {
			return err
		}
	}
	if enabled != wasEnabled {
		action := "social_provider.disabled"
		if enabled {
			action = "social_provider.enabled"
		}
		if err := recordProviderChange(ctx, tx, by, organizationID, id, action, map[string]any{"provider": provider}); err != nil {
			return err
		}
	}
	return nil
}

// DeleteProvider removes the organization's provider. Refused with
// ErrSocialProviderInUse while anyone in the organization can sign in only
// through it, and with ErrNotFound when the organization has no such provider.
func (s *Service) DeleteProvider(ctx context.Context, organizationID uuid.UUID, provider string, by audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	current, err := q.LockSocialProvider(ctx, dbgen.LockSocialProviderParams{OrganizationID: organizationID, Provider: provider})
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound
	} else if err != nil {
		return err
	}
	deps, err := q.SocialProviderDependents(ctx, dbgen.SocialProviderDependentsParams{OrganizationID: organizationID, Provider: provider})
	if err != nil {
		return err
	}
	if deps.Dependent > 0 {
		return ErrProviderInUse.WithMetadata(map[string]any{"people": deps.Dependent})
	}
	if err := q.DeleteSocialProvider(ctx, dbgen.DeleteSocialProviderParams{ID: current.ID, OrganizationID: organizationID}); err != nil {
		return err
	}
	if err := recordProviderChange(ctx, tx, by, organizationID, current.ID, "social_provider.deleted", map[string]any{
		"provider": provider, "linked_identities_kept": deps.Linked,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
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
	p, err := h.Service.UpdateProvider(r.Context(), organizationID, chi.URLParam(r, "provider"), in, audit.ActorOf(r))
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
	if err := h.Service.DeleteProvider(r.Context(), organizationID, chi.URLParam(r, "provider"), audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// CreateProviderInput adds a provider, or replaces the settings of one the
// organization already has. Replacing keeps whether it is switched on, and an
// empty ClientSecret keeps the stored secret (a new provider needs one).
// DiscoveryURL is an OpenID Connect provider's alone. For Apple, ClientID is
// the Services ID and ClientSecret the .p8 private key, with AppleTeamID and
// AppleKeyID; the client secret is signed from them for each sign-in.
// Actor is who saved it, for the audit record.
type CreateProviderInput struct {
	audit.Actor    `json:"-"`
	OrganizationID uuid.UUID `json:"organization_id"`
	Provider       string    `json:"provider"`
	ClientID       string    `json:"client_id"`
	ClientSecret   string    `json:"client_secret"`
	DiscoveryURL   string    `json:"discovery_url"`
	AppleTeamID    string    `json:"apple_team_id"`
	AppleKeyID     string    `json:"apple_key_id"`
}

// checkAppleKey refuses an Apple private key, team ID and key ID that can't
// sign a client secret.
func checkAppleKey(servicesID, teamID, keyID, privateKey string) error {
	if _, err := appleClientSecret(servicesID, teamID, keyID, privateKey); err != nil {
		return errs.ErrValidationFailed.WithFields([]errs.FieldError{{
			Field: "client_secret", Code: "invalid", Message: "Enter the .p8 private key Apple gave for the key ID.",
		}})
	}
	return nil
}

// UpsertProvider adds or updates one of the organization's social providers.
func (s *Service) UpsertProvider(ctx context.Context, in CreateProviderInput) (*Provider, error) {
	kind := adapterKind(in.Provider)
	if kind == kindOIDC {
		if _, err := s.egress.ValidateHTTPURL(in.DiscoveryURL); err != nil {
			return nil, ErrProviderNoDiscovery
		}
	} else {
		in.DiscoveryURL = ""
	}
	if kind != kindApple {
		in.AppleTeamID, in.AppleKeyID = "", ""
	}
	if strings.TrimSpace(in.Provider) == "" || strings.TrimSpace(in.ClientID) == "" {
		return nil, errs.ErrValidationFailed.WithFields([]errs.FieldError{
			{Field: "client_id", Code: "required", Message: "Enter the provider and its client ID."},
		})
	}
	if kind == kindApple {
		if strings.TrimSpace(in.AppleTeamID) == "" || strings.TrimSpace(in.AppleKeyID) == "" {
			return nil, errs.ErrValidationFailed.WithFields([]errs.FieldError{
				{Field: "apple_team_id", Code: "required", Message: "Enter Apple's team ID and key ID."},
			})
		}
		if in.ClientSecret != "" {
			if err := checkAppleKey(in.ClientID, in.AppleTeamID, in.AppleKeyID, in.ClientSecret); err != nil {
				return nil, err
			}
		}
	}
	replaceSecret := in.ClientSecret != ""
	var ciphertext, nonce []byte
	if replaceSecret {
		var err error
		if ciphertext, nonce, err = s.sealSecret(in.OrganizationID, in.Provider, in.ClientSecret); err != nil {
			return nil, err
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	_, err = q.LockSocialProvider(ctx, dbgen.LockSocialProviderParams{OrganizationID: in.OrganizationID, Provider: in.Provider})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	existing := err == nil
	if !existing && !replaceSecret {
		return nil, errs.ErrValidationFailed.WithFields([]errs.FieldError{
			{Field: "client_secret", Code: "required", Message: "Enter the client secret."},
		})
	}
	var r dbgen.InsertSocialProviderRow
	if existing {
		// Replacing keeps whether the provider is switched on, and the stored
		// secret when none is given.
		var replaced dbgen.ReplaceSocialProviderRow
		replaced, err = q.ReplaceSocialProvider(ctx, dbgen.ReplaceSocialProviderParams{
			OrganizationID: in.OrganizationID, Provider: in.Provider, ClientID: in.ClientID, DiscoveryUrl: in.DiscoveryURL,
			ReplaceSecret: replaceSecret, ClientSecretCt: ciphertext, ClientSecretNonce: nonce,
			AppleTeamID: in.AppleTeamID, AppleKeyID: in.AppleKeyID,
		})
		r = dbgen.InsertSocialProviderRow(replaced)
	} else {
		r, err = q.InsertSocialProvider(ctx, dbgen.InsertSocialProviderParams{
			OrganizationID: in.OrganizationID, Provider: in.Provider, ClientID: in.ClientID,
			ClientSecretCt: ciphertext, ClientSecretNonce: nonce, DiscoveryUrl: in.DiscoveryURL,
			AppleTeamID: in.AppleTeamID, AppleKeyID: in.AppleKeyID,
		})
		if postgres.IsUnique(err) {
			// Added by a concurrent save; this one is a replacement after all.
			return nil, errs.ErrConflict
		}
	}
	if err != nil {
		return nil, err
	}
	action, meta := "social_provider.created", map[string]any{"provider": in.Provider}
	if existing {
		action = "social_provider.updated"
		meta["fields"] = []string{"client_id", "discovery_url"}
		meta["secret_replaced"] = replaceSecret
	}
	if err := recordProviderChange(ctx, tx, in.Actor, in.OrganizationID, r.ID, action, meta); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	p := Provider{
		ID:             r.ID,
		OrganizationID: r.OrganizationID,
		Provider:       r.Provider,
		Kind:           kind,
		ClientID:       r.ClientID,
		DiscoveryURL:   r.DiscoveryUrl,
		AppleTeamID:    r.AppleTeamID,
		AppleKeyID:     r.AppleKeyID,
		Enabled:        r.Enabled,
		CreatedAt:      r.CreatedAt,
	}
	return &p, nil
}

// ListProviders returns the organization's social providers.
func (s *Service) ListProviders(ctx context.Context, organizationID uuid.UUID) ([]Provider, error) {
	rows, err := s.q.ListSocialProviders(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]Provider, len(rows))
	for i, r := range rows {
		out[i] = Provider{
			ID:             r.ID,
			OrganizationID: r.OrganizationID,
			Provider:       r.Provider,
			Kind:           adapterKind(r.Provider),
			ClientID:       r.ClientID,
			DiscoveryURL:   r.DiscoveryUrl,
			AppleTeamID:    r.AppleTeamID,
			AppleKeyID:     r.AppleKeyID,
			Enabled:        r.Enabled,
			CreatedAt:      r.CreatedAt,
		}
	}
	return out, nil
}

// checkTrust refuses pointing the organization's OpenID Connect provider name
// at discoveryURL, unless that is where it already looks, when the caller may
// not act on every administrator linked to it: the provider signs them in on
// what that URL serves. A provider set up again under a name it had before
// gets its earlier links back, so it counts as a change too.
func (h *Handler) checkTrust(r *http.Request, organizationID uuid.UUID, name, discoveryURL string) error {
	if adapterKind(name) != kindOIDC {
		return nil
	}
	ctx := r.Context()
	current, err := h.Service.q.SocialProviderDiscoveryURL(ctx, dbgen.SocialProviderDiscoveryURLParams{OrganizationID: organizationID, Provider: name})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err == nil && strings.TrimSpace(discoveryURL) == current {
		return nil
	}
	return identitylink.CheckTrustChange(ctx, h.Service.pool, httpx.PrincipalFromCtx(ctx), h.ActOnCheck, organizationID, uuid.Nil, name)
}

func (h *Handler) upsertProvider(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in CreateProviderInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.OrganizationID = organizationID // scope comes from the principal, never the body
	in.Actor = audit.ActorOf(r)
	if err := h.checkTrust(r, organizationID, in.Provider, in.DiscoveryURL); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	p, err := h.Service.UpsertProvider(r.Context(), in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

func (h *Handler) listProviders(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ListProviders(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

// Provider is an organization's social identity provider, without its secret. Kind is
// oidc, found by DiscoveryURL, or the adapter its name picks (github,
// facebook, x, discord or apple); Apple's names its team and key.
type Provider struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	Provider       string    `json:"provider"`
	Kind           string    `json:"kind"`
	ClientID       string    `json:"client_id"`
	DiscoveryURL   *string   `json:"discovery_url"`
	AppleTeamID    *string   `json:"apple_team_id,omitempty"`
	AppleKeyID     *string   `json:"apple_key_id,omitempty"`
	Enabled        bool      `json:"enabled"`
	CreatedAt      time.Time `json:"created_at"`
}
