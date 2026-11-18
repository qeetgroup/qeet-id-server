package adminportal

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/adminportal/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

func normalizeCapabilities(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, ErrCapabilitiesRequired
	}
	var out []string
	for _, c := range in {
		c = strings.ToLower(strings.TrimSpace(c))
		if !slices.Contains(validCapabilities, c) {
			return nil, ErrCapabilityUnknown
		}
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out, nil
}

// linkTTL returns how long a new link lasts: d, or defaultTTL when d is zero
// (none was asked for). A lifetime outside minTTL..maxTTL is refused, with the
// bounds, rather than quietly changed.
func linkTTL(d time.Duration) (time.Duration, error) {
	if d == 0 {
		return defaultTTL, nil
	}
	if d < minTTL || d > maxTTL {
		return 0, ErrTTLOutOfRange.WithMetadata(map[string]any{
			"min_seconds": int(minTTL.Seconds()), "max_seconds": int(maxTTL.Seconds()),
		})
	}
	return d, nil
}

// Generate mints a new admin portal link, made by actor. The raw token is
// returned exactly once — only the hash is persisted.
func (s *Service) Generate(ctx context.Context, organizationID uuid.UUID, capabilities []string, ttl time.Duration, actor audit.Actor) (*Link, string, error) {
	caps, err := normalizeCapabilities(capabilities)
	if err != nil {
		return nil, "", err
	}
	ttl, err = linkTTL(ttl)
	if err != nil {
		return nil, "", err
	}
	raw, hash, err := codes.URLToken()
	if err != nil {
		return nil, "", err
	}
	expires := time.Now().UTC().Add(ttl)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx)
	row, err := s.q.WithTx(tx).InsertAdminPortalLink(ctx, dbgen.InsertAdminPortalLinkParams{
		OrganizationID: organizationID,
		TokenHash:      hash,
		Capabilities:   caps,
		CreatedBy:      actor.UserID,
		ExpiresAt:      expires,
	})
	if err != nil {
		return nil, "", err
	}
	l := &Link{
		ID:             row.ID,
		OrganizationID: row.OrganizationID,
		Capabilities:   row.Capabilities,
		CreatedBy:      row.CreatedBy,
		ExpiresAt:      row.ExpiresAt,
		RevokedAt:      row.RevokedAt,
		LastUsedAt:     row.LastUsedAt,
		CreatedAt:      row.CreatedAt,
	}
	if err := recordLinkChange(ctx, tx, actor, organizationID, l.ID, "admin_portal.link_generated", map[string]any{"capabilities": l.Capabilities}); err != nil {
		return nil, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	return l, raw, nil
}

// recordLinkChange audits, in tx, actor's change to organizationID's link id.
func recordLinkChange(ctx context.Context, tx pgx.Tx, actor audit.Actor, organizationID, id uuid.UUID, action string, meta map[string]any) error {
	return audit.Record(ctx, tx, actor.Event(organizationID, action, "admin_portal_link", id, meta))
}

// URL builds the shareable link for a freshly-generated raw token: the hosted
// enterprise-setup page, with the token in the fragment so it never reaches a
// server log.
func (s *Service) URL(rawToken string) string {
	return s.PortalURL() + "#token=" + rawToken
}

// PortalURL returns the hosted enterprise-setup page's address.
func (s *Service) PortalURL() string { return s.loginBaseURL + "/enterprise-setup" }

// List returns the organization's portal links.
func (s *Service) List(ctx context.Context, organizationID uuid.UUID) ([]Link, error) {
	rows, err := s.q.ListAdminPortalLinksByOrganization(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]Link, len(rows))
	for i, r := range rows {
		out[i] = Link{
			ID:             r.ID,
			OrganizationID: r.OrganizationID,
			Capabilities:   r.Capabilities,
			CreatedBy:      r.CreatedBy,
			ExpiresAt:      r.ExpiresAt,
			RevokedAt:      r.RevokedAt,
			LastUsedAt:     r.LastUsedAt,
			CreatedAt:      r.CreatedAt,
		}
	}
	return out, nil
}

// Revoke revokes one of the organization's portal links, recorded as actor's.
func (s *Service) Revoke(ctx context.Context, organizationID, id uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).RevokeAdminPortalLink(ctx, dbgen.RevokeAdminPortalLinkParams{
		ID:             id,
		OrganizationID: organizationID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrLinkNotFound
	}
	if err := recordLinkChange(ctx, tx, actor, organizationID, id, "admin_portal.link_revoked", nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (h *Handler) generate(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, ErrActorRequired)
		return
	}
	var in struct {
		Capabilities []string `json:"capabilities"`
		TTLSeconds   int      `json:"ttl_seconds"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	link, raw, err := h.Service.Generate(r.Context(), organizationID, in.Capabilities, time.Duration(in.TTLSeconds)*time.Second, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"link":  link,
		"token": raw,
		"url":   h.Service.URL(raw),
	})
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.List(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrIDInvalid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.Revoke(r.Context(), organizationID, id, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
