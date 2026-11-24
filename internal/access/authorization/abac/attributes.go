package abac

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/abac/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// AttributeBag holds the per-namespace attribute maps for one evaluation.
// The outer key is the namespace ("subject", "resource", "context");
// the inner map carries the concrete attributes for that namespace.
type AttributeBag map[string]map[string]any

// SubjectAttributes is the subject namespace the platform supplies when it
// decides for a user itself (decide.Decider): who they are, never anything the
// caller chose, so a deny written against subject.id binds wherever it applies.
func SubjectAttributes(userID string, organizationID uuid.UUID) map[string]any {
	return map[string]any{"id": userID, "type": "user", "organization_id": organizationID.String()}
}

// Request is what the platform itself knows of a decision it makes for a user:
// who they are and, when it is the user's own call, its session and address.
// Nothing in it comes from what the caller sends.
type Request struct {
	Subject        string    // the user's id as the engines name it
	UserID         uuid.UUID // the same, parsed; uuid.Nil when it names no platform user
	OrganizationID uuid.UUID // the organization decided in
	SessionID      uuid.UUID // the user's own session (uuid.Nil: none)
	MFA            bool      // the call itself proved a second factor (a hosted-login sign-in that did)
	IP             string    // the client address ("": not the user's own call)
}

// OwnRequest is the Request for userID's own call in ctx: with the call's
// session, second factor and client address when ctx carries userID's
// principal in organizationID, and without them otherwise.
func OwnRequest(ctx context.Context, userID, organizationID uuid.UUID) Request {
	r := Request{Subject: userID.String(), UserID: userID, OrganizationID: organizationID}
	p := httpx.PrincipalFromCtx(ctx)
	if p == nil || p.UserID == nil || *p.UserID != userID || p.OrganizationID == nil || *p.OrganizationID != organizationID {
		return r
	}
	r.IP = httpx.ClientIPFromContext(ctx)
	r.MFA = p.SignedInAt != nil
	// An application's token names no session of the user's own.
	if p.SessionID != nil && p.ClientID == "" && (p.ActorType == "" || p.ActorType == "user") {
		r.SessionID = *p.SessionID
	}
	return r
}

// PlatformAttributes is the subject and context namespaces the platform
// supplies for r: subject id, type, organization_id, and the groups and roles (by
// name) the user holds in the organization; context mfa and ip when the call
// is the user's own. An attribute it can't know is left out, so it is unknown.
func (s *Service) PlatformAttributes(ctx context.Context, r Request) (subject, ctxAttrs map[string]any, err error) {
	subject, ctxAttrs = SubjectAttributes(r.Subject, r.OrganizationID), map[string]any{}
	if r.UserID != uuid.Nil {
		rows, err := s.q.ListSubjectMemberships(ctx, dbgen.ListSubjectMembershipsParams{OrganizationID: r.OrganizationID, UserID: r.UserID})
		if err != nil {
			return nil, nil, err
		}
		groups, roles := []any{}, []any{}
		for _, row := range rows {
			if row.Kind == "group" {
				groups = append(groups, row.Name)
			} else {
				roles = append(roles, row.Name)
			}
		}
		subject["groups"], subject["roles"] = groups, roles
	}
	if r.IP != "" {
		ctxAttrs["ip"] = r.IP
	}
	switch {
	case r.MFA:
		ctxAttrs["mfa"] = true
	case r.SessionID != uuid.Nil && r.UserID != uuid.Nil:
		met, err := s.q.SessionSecondFactorMet(ctx, dbgen.SessionSecondFactorMetParams{SessionID: r.SessionID, UserID: r.UserID, OrganizationID: r.OrganizationID})
		switch {
		case err == nil:
			ctxAttrs["mfa"] = met
		case !errors.Is(err, pgx.ErrNoRows):
			return nil, nil, err
		}
	}
	return subject, ctxAttrs, nil
}

// attributeBag builds the bag policies see for in: the resource's type, id and attrs in one namespace,
// the action's name and attrs in another. The decided type, id and name win over a same-named
// attribute, so a condition never sees a resource the policies weren't chosen for.
func attributeBag(in EvaluationInput) AttributeBag {
	resourceAttrs := withAttrs(in.Resource.Attrs, map[string]any{"type": in.Resource.Type, "id": in.Resource.ID})
	subject := in.Subject
	if subject == nil {
		subject = map[string]any{}
	}
	ctxAttrs := in.Context
	if ctxAttrs == nil {
		ctxAttrs = map[string]any{}
	}
	return AttributeBag{
		"subject":  subject,
		"resource": resourceAttrs,
		"action":   withAttrs(in.ActionAttrs, map[string]any{"name": in.Action}),
		"context":  ctxAttrs,
	}
}

// withAttrs is attrs with over set on top: over wins where both name a key.
func withAttrs(attrs, over map[string]any) map[string]any {
	out := make(map[string]any, len(attrs)+len(over))
	for k, v := range attrs {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}
