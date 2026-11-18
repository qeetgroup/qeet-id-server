package domainverify

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Domain capture: an organization that manages a domain, has switched SSO on for it and has an active
// SAML or LDAP connection makes everyone on that domain sign in through its identity provider. Their
// own sign-in methods are refused, except for the break-glass members its owners name (so an IdP
// outage can't lock everyone out) and the administrators single sign-on never takes over by address.

// OwnerChecker reports whether userID holds organizationID's owner role. Satisfied by
// *rbac.Repository.
type OwnerChecker interface {
	IsOwner(ctx context.Context, userID, organizationID uuid.UUID) (bool, error)
}

// errBreakGlassOwnerOnly refuses a break-glass change by anyone but an owner.
var errBreakGlassOwnerOnly = errs.ErrRBACOwnerOnly.WithMessage("Only an owner can choose who keeps signing in without single sign-on.")

// RefuseCaptured returns errs.ErrAuthSSORequired, naming the organization's active connections in its
// metadata, when email's domain is captured and its account isn't exempt. Every address on the
// domain that isn't exempt gets the same answer from the same queries, account or not.
func (s *Service) RefuseCaptured(ctx context.Context, email string) error {
	// A verified domain belongs to one organization, whoever asks.
	ctx = postgres.AcrossOrganizations(ctx)
	email = strings.TrimSpace(email)
	managed, ok, err := ManagingDomain(ctx, s.pool, email)
	if err != nil || !ok || !managed.SSO {
		return err
	}
	ex, err := s.q.GetCaptureExemption(ctx, dbgen.GetCaptureExemptionParams{
		OrganizationID: managed.OrganizationID, MemberPermissions: s.memberPermissions, Email: email,
	})
	if err != nil {
		return err
	}
	if !ex.Sso || ex.BreakGlass || ex.UnadoptableAdmin {
		return nil
	}
	conns, err := s.q.ListActiveSSOConnections(ctx, managed.OrganizationID)
	if err != nil {
		return err
	}
	list := make([]map[string]any, 0, len(conns))
	for _, c := range conns {
		list = append(list, map[string]any{"id": c.ID, "protocol": c.Protocol, "name": c.Name})
	}
	return errs.ErrAuthSSORequired.WithMetadata(map[string]any{"connections": list})
}

// BreakGlassMember is a member who keeps their own sign-in methods on a
// captured domain.
type BreakGlassMember struct {
	UserID      uuid.UUID  `json:"user_id"`
	Email       string     `json:"email"`
	DisplayName *string    `json:"display_name,omitempty"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// ListBreakGlass returns organizationID's break-glass members.
func (s *Service) ListBreakGlass(ctx context.Context, organizationID uuid.UUID) ([]BreakGlassMember, error) {
	rows, err := s.q.ListBreakGlassMembers(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]BreakGlassMember, 0, len(rows))
	for _, r := range rows {
		m := BreakGlassMember{UserID: r.UserID, Email: r.Email, DisplayName: r.DisplayName, CreatedAt: r.CreatedAt}
		m.CreatedBy = r.CreatedBy
		out = append(out, m)
	}
	return out, nil
}

// requireOwner refuses actor unless they are a person holding organizationID's owner
// role; a credential acting for one is refused too.
func (s *Service) requireOwner(ctx context.Context, organizationID uuid.UUID, actor audit.Actor) error {
	if actor.UserID == nil || actor.Type != "user" {
		return errBreakGlassOwnerOnly
	}
	owner, err := s.owners.IsOwner(ctx, *actor.UserID, organizationID)
	if err != nil {
		return err
	}
	if !owner {
		return errBreakGlassOwnerOnly
	}
	return nil
}

// SetBreakGlass makes userID, a member of organizationID, a break-glass member (on)
// or an ordinary one, as actor, who must be an owner. A change is recorded in
// the audit trail in the same transaction; asking for the current state
// changes and records nothing.
func (s *Service) SetBreakGlass(ctx context.Context, organizationID, userID uuid.UUID, on bool, actor audit.Actor) error {
	if err := s.requireOwner(ctx, organizationID, actor); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	var changed int64
	action := "domain.break_glass_removed"
	if on {
		member, err := q.IsOrganizationMember(ctx, dbgen.IsOrganizationMemberParams{UserID: userID, OrganizationID: organizationID})
		if err != nil {
			return err
		}
		if !member {
			return ErrNotMember
		}
		if changed, err = q.InsertBreakGlassMember(ctx, dbgen.InsertBreakGlassMemberParams{OrganizationID: organizationID, UserID: userID, CreatedBy: actor.UserID}); err != nil {
			return err
		}
		action = "domain.break_glass_added"
	} else if changed, err = q.DeleteBreakGlassMember(ctx, dbgen.DeleteBreakGlassMemberParams{OrganizationID: organizationID, UserID: userID}); err != nil {
		return err
	}
	if changed == 0 {
		return nil
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, action, "user", userID, nil)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (h *Handler) listBreakGlass(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ListBreakGlass(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) addBreakGlass(w http.ResponseWriter, r *http.Request) { h.setBreakGlass(w, r, true) }

func (h *Handler) removeBreakGlass(w http.ResponseWriter, r *http.Request) {
	h.setBreakGlass(w, r, false)
}

func (h *Handler) setBreakGlass(w http.ResponseWriter, r *http.Request, on bool) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	userID, err := httpx.PathUUID(r, "userID", errs.ErrBadRequest.WithDetail("invalid user id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.SetBreakGlass(r.Context(), organizationID, userID, on, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// DiscoveredConnection is a connection an address's domain signs in through.
// LoginPath, below the API's address, starts its sign-in: a browser goes to it
// (method redirect), or the person's directory login name and password are
// posted to it (method credentials).
type DiscoveredConnection struct {
	ID        uuid.UUID `json:"id"`
	Protocol  string    `json:"protocol"`
	Name      string    `json:"name"`
	Method    string    `json:"method"`
	LoginPath string    `json:"login_path"`
	// SessionPath, for a credentials connection, takes the same user name and password from the
	// hosted login and answers with its session instead of a token pair.
	SessionPath string `json:"session_path,omitempty"`
}

// Discovery is where an address signs in. SSO is true when the organization managing its domain sends
// the domain to its identity provider, through Connections. Organization is that organization's name,
// for the sign-in page; like the connections' names it is the same for every address on the domain.
type Discovery struct {
	SSO          bool                   `json:"sso"`
	Organization string                 `json:"organization_name,omitempty"`
	Connections  []DiscoveredConnection `json:"connections"`
}

// Discover returns where email signs in, judged by its domain alone: every
// address on a domain gets the same answer, whether or not it has an account
// or is exempt from single sign-on.
func (s *Service) Discover(ctx context.Context, email string) (*Discovery, error) {
	ctx = postgres.AcrossOrganizations(ctx)
	out := &Discovery{Connections: []DiscoveredConnection{}}
	managed, ok, err := ManagingDomain(ctx, s.pool, strings.TrimSpace(email))
	if err != nil || !ok || !managed.SSO {
		return out, err
	}
	conns, err := s.q.ListActiveSSOConnections(ctx, managed.OrganizationID)
	if err != nil {
		return nil, err
	}
	for _, c := range conns {
		d := DiscoveredConnection{ID: c.ID, Protocol: c.Protocol, Name: c.Name, Method: "redirect"}
		switch c.Protocol {
		case "saml":
			d.LoginPath = "/saml/login/" + c.ID.String()
		case "oidc":
			d.LoginPath = "/v1/oidc-connections/" + c.ID.String() + "/login"
		case "ldap":
			d.Method, d.LoginPath = "credentials", "/ldap/"+c.ID.String()+"/authenticate"
			d.SessionPath = "/ldap/" + c.ID.String() + "/session"
		}
		out.Connections = append(out.Connections, d)
	}
	out.SSO = len(out.Connections) > 0
	if out.SSO {
		name, err := s.q.OrganizationName(ctx, managed.OrganizationID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		out.Organization = name
	}
	return out, nil
}

func (h *Handler) discover(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email string `json:"email"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if !strings.Contains(in.Email, "@") {
		httpx.WriteError(w, r, errs.ErrValidationFailed.WithFields([]errs.FieldError{{
			Field: "email", Code: "invalid", Message: "Enter an email address.",
		}}))
		return
	}
	out, err := h.Service.Discover(r.Context(), in.Email)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
