package social

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/social/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// ExternalIdentity is a social account linked to a user.
type ExternalIdentity struct {
	ID             uuid.UUID `json:"id"`
	UserID         uuid.UUID `json:"user_id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	Provider       string    `json:"provider"`
	Subject        string    `json:"subject"`
	Email          *string   `json:"email"`
	LinkedAt       time.Time `json:"linked_at"`
}

// ListIdentities returns the social accounts linked to the user in the organization.
func (s *Service) ListIdentities(ctx context.Context, userID, organizationID uuid.UUID) ([]ExternalIdentity, error) {
	// Organization-scoped so one organization can't read another's linked identities;
	// the deleted_at join keeps soft-deleted users out of admin lookups.
	rows, err := s.q.ListExternalIdentities(ctx, dbgen.ListExternalIdentitiesParams{
		UserID:         userID,
		OrganizationID: organizationID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]ExternalIdentity, len(rows))
	for i, r := range rows {
		out[i] = ExternalIdentity{
			ID:             r.ID,
			UserID:         r.UserID,
			OrganizationID: r.OrganizationID,
			Provider:       r.Provider,
			Subject:        r.Subject,
			Email:          r.Email,
			LinkedAt:       r.LinkedAt,
		}
	}
	return out, nil
}

// Unlink is an administrator removing an identity linked to an account in
// their organization: organization-scoped, so an identity can only be removed within
// its organization. Refused when mayChange refuses the account (it runs before the
// transaction opens), and, recorded, when it is the account's only way to sign
// in.
func (s *Service) Unlink(ctx context.Context, id, organizationID uuid.UUID, by user.Remover, mayChange func(owner uuid.UUID) error) error {
	// The account's other ways to sign in span its organizations.
	ctx = postgres.AcrossOrganizations(ctx)
	owner, err := s.q.ExternalIdentityOwner(ctx, dbgen.ExternalIdentityOwnerParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound
	} else if err != nil {
		return err
	}
	if err := mayChange(owner); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	methods, err := user.LockSignInMethods(ctx, tx, owner)
	if err != nil {
		return err
	}
	n, err := s.q.WithTx(tx).DeleteExternalIdentity(ctx, dbgen.DeleteExternalIdentityParams{
		ID:             id,
		OrganizationID: organizationID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	if methods.Total() <= 1 {
		_ = tx.Rollback(ctx)
		tid := organizationID
		return user.RefuseLastMethodRemoval(ctx, s.pool, owner, &tid, "linked_identity", id, by)
	}
	return tx.Commit(ctx)
}

// ListIdentitiesForUser returns the caller's connected social accounts. Console
// accounts are organization-less, so this reads the platform identities table (which
// platform sign-in and the link flow populate) rather than the organization-scoped
// account.external_identities.
func (s *Service) ListIdentitiesForUser(ctx context.Context, userID uuid.UUID) ([]ExternalIdentity, error) {
	rows, err := s.q.ListPlatformSocialIdentitiesForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]ExternalIdentity, len(rows))
	for i, r := range rows {
		out[i] = ExternalIdentity{
			ID:       r.ID,
			UserID:   r.UserID,
			Provider: r.Provider,
			Subject:  r.Subject,
			Email:    r.Email,
			LinkedAt: r.LinkedAt,
		}
	}
	return out, nil
}

// UnlinkForUser removes one of the caller's connected platform social
// accounts. ErrNotFound when it is not theirs (nothing is removed); refused,
// and recorded, when it is their account's only way to sign in.
func (s *Service) UnlinkForUser(ctx context.Context, id, userID uuid.UUID, by user.Remover) error {
	// The account's other ways to sign in span its organizations.
	ctx = postgres.AcrossOrganizations(ctx)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	methods, err := user.LockSignInMethods(ctx, tx, userID)
	if err != nil {
		return err
	}
	n, err := s.q.WithTx(tx).DeletePlatformSocialIdentityForUser(ctx, dbgen.DeletePlatformSocialIdentityForUserParams{
		ID:     id,
		UserID: userID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	if methods.Total() <= 1 {
		_ = tx.Rollback(ctx)
		return user.RefuseLastMethodRemoval(ctx, s.pool, userID, nil, "linked_identity", id, by)
	}
	return tx.Commit(ctx)
}

func (h *Handler) listIdentities(w http.ResponseWriter, r *http.Request) {
	uid, err := httpx.PathUUID(r, "userID", errs.ErrBadRequest.WithDetail("invalid userID"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ListIdentities(r.Context(), uid, organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) unlink(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var by user.Remover
	if p := httpx.PrincipalFromCtx(r.Context()); p != nil {
		by.UserID = p.UserID
	}
	by.IP, by.UserAgent, by.RequestID = httpx.ClientIP(r), r.UserAgent(), httpx.RequestID(r)
	// Only an administrator who outranks the account takes a way in from it.
	mayChange := func(owner uuid.UUID) error { return httpx.ActOn(r, h.ActOnCheck, organizationID, owner) }
	if err := h.Service.Unlink(r.Context(), id, organizationID, by, mayChange); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listMyIdentities lists the social logins on the caller's own account (no organization).
func (h *Handler) listMyIdentities(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	out, err := h.Service.ListIdentitiesForUser(r.Context(), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

// linkStart begins an authenticated link ceremony: it stashes the caller in the
// OAuth state and returns the provider's authorize URL for the browser to
// navigate to. Unlike /social/{provider}/start (public login), the callback for
// this ceremony attaches the identity to the caller instead of logging in.
func (h *Handler) linkStart(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	provider := chi.URLParam(r, "provider")
	if !h.Service.PlatformProviderEnabled(provider) {
		httpx.WriteError(w, r, errs.ErrSocialProviderNotConfigured)
		return
	}
	authURL, err := h.Service.BeginPlatformLink(r.Context(), provider, h.callbackURL(r, provider), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"authorize_url": authURL})
}

type linkCompleteInput struct {
	Code string `json:"code"`
}

// linkComplete attaches the provider a link callback returned (held under the
// link_code the account page was sent back with) to the caller — only when the
// caller is the account that began the link.
func (h *Handler) linkComplete(w http.ResponseWriter, r *http.Request) {
	userID, err := httpx.RequireUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in linkCompleteInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	provider, err := h.Service.CompletePlatformLink(r.Context(), in.Code, userID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"provider": provider})
}

// unlinkMine removes a social login from the caller's own account.
func (h *Handler) unlinkMine(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	id, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	by := user.Remover{UserID: p.UserID, IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)}
	if err := h.Service.UnlinkForUser(r.Context(), id, *p.UserID, by); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
