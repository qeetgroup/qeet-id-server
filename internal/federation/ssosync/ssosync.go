// Package ssosync keeps an account in step with what each SAML or LDAP sign-in
// asserts about it: the profile its connection maps, and its place in the
// organisation's groups. Sync changes only memberships the same connection's
// sign-ins made, never one an administrator, an import or SCIM made, and never
// reaches a group holding the owner role or an administrative permission.
// Every change is audited in the sign-in's transaction.
package ssosync

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/identitylink"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ssosync/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/pgxerr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
)

const (
	maxDisplayName = 200  // longest display name a sign-in sets, in characters
	maxGroupValue  = 1024 // longest asserted group matched, in bytes
)

// SignIn is what a sign-in through a connection asserted about the account it
// signs in. GroupsWithheld says the identity provider left the groups out (as
// Microsoft Entra ID does past its limit), so memberships stay as they are.
type SignIn struct {
	TenantID       uuid.UUID
	UserID         uuid.UUID
	ConnectionID   uuid.UUID
	Provider       string // "saml" or "ldap": who the audit records name
	DisplayName    string // "" when none was asserted
	Email          string // the asserted address
	EmailManaged   bool   // Email is on a domain the organisation manages
	Groups         []string
	GroupsWithheld bool
	Actor          audit.Actor
}

// Apply refreshes the account's profile and groups from in, within the
// sign-in's transaction tx.
func Apply(ctx context.Context, tx pgx.Tx, in SignIn) error {
	if err := refreshProfile(ctx, tx, in); err != nil {
		return err
	}
	return syncGroups(ctx, tx, in)
}

// refreshProfile sets the asserted display name, and the asserted address when
// refreshEmail allows it, recording what changed.
func refreshProfile(ctx context.Context, tx pgx.Tx, in SignIn) error {
	q := dbgen.New(tx)
	current, err := q.GetAccountProfile(ctx, dbgen.GetAccountProfileParams{ID: in.UserID, TenantID: in.TenantID})
	if err != nil {
		return err
	}
	changed := map[string]any{}
	name := strings.TrimSpace(in.DisplayName)
	if name != "" && utf8.RuneCountInString(name) <= maxDisplayName && (current.DisplayName == nil || *current.DisplayName != name) {
		if err := q.SetDisplayName(ctx, dbgen.SetDisplayNameParams{DisplayName: &name, ID: in.UserID, TenantID: in.TenantID}); err != nil {
			return err
		}
		changed["display_name_changed"] = true
	}
	emailChanged, err := refreshEmail(ctx, tx, in, current.Email)
	if err != nil {
		return err
	}
	if emailChanged {
		changed["email_changed"] = true
	}
	if len(changed) == 0 {
		return nil
	}
	changed["connection_id"] = in.ConnectionID
	changed["source"] = in.Provider
	return audit.Record(ctx, tx, in.Actor.Event(in.TenantID, "user.updated", "user", in.UserID, changed))
}

// refreshEmail moves the account to the asserted address under the rules an
// address is adopted by: it must be on a domain the organisation manages, not
// be another account's, and the account mustn't administer the organisation,
// or the connection could take over an administrator's recovery. Recovery links
// sent to the old address stop working.
func refreshEmail(ctx context.Context, tx pgx.Tx, in SignIn, current string) (bool, error) {
	email := strings.ToLower(strings.TrimSpace(in.Email))
	if email == "" || !in.EmailManaged || strings.EqualFold(email, current) {
		return false, nil
	}
	admin, err := identitylink.Administers(ctx, tx, in.UserID, in.TenantID)
	if err != nil || admin {
		return false, err
	}
	// A savepoint, so an address another account holds leaves the sign-in be.
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = savepoint.Rollback(ctx) }()
	// Before the change: the links are found by the address they went to.
	if err := auth.ExpireRecoveryLinks(ctx, savepoint, in.UserID); err != nil {
		return false, err
	}
	if err := dbgen.New(savepoint).SetEmail(ctx, dbgen.SetEmailParams{Email: email, ID: in.UserID, TenantID: in.TenantID}); err != nil {
		if pgxerr.IsUnique(err) {
			return false, nil
		}
		return false, err
	}
	return true, savepoint.Commit(ctx)
}

// syncGroups adds the person to the groups the asserted groups reach and takes
// them out of those the connection's sign-ins put them in that they no longer
// reach, recording each change with its event.
func syncGroups(ctx context.Context, tx pgx.Tx, in SignIn) error {
	if in.GroupsWithheld {
		return nil
	}
	q := dbgen.New(tx)
	var targets []uuid.UUID
	if values := groupValues(in.Groups); len(values) > 0 {
		var err error
		targets, err = q.SyncTargets(ctx, dbgen.SyncTargetsParams{
			TenantID: in.TenantID, ConnectionID: in.ConnectionID,
			MemberPermissions: identitylink.MemberPermissions(), IdpGroups: values,
		})
		if err != nil {
			return err
		}
	}
	current, err := q.SyncedMemberships(ctx, dbgen.SyncedMembershipsParams{TenantID: in.TenantID, UserID: in.UserID, ConnectionID: in.ConnectionID})
	if err != nil {
		return err
	}
	held := make(map[uuid.UUID]bool, len(current))
	for _, id := range current {
		held[id] = true
	}
	wanted := make(map[uuid.UUID]bool, len(targets))
	for _, id := range targets {
		wanted[id] = true
		if held[id] {
			continue
		}
		n, err := q.AddSyncedMembership(ctx, dbgen.AddSyncedMembershipParams{GroupID: id, UserID: in.UserID, TenantID: in.TenantID, ConnectionID: in.ConnectionID})
		if err != nil {
			return err
		}
		if n == 1 {
			if err := recordMembership(ctx, tx, in.Actor, in.TenantID, id, in.UserID, in.ConnectionID, in.Provider, "group.member_added"); err != nil {
				return err
			}
		}
	}
	for _, id := range current {
		if wanted[id] {
			continue
		}
		n, err := q.RemoveSyncedMembership(ctx, dbgen.RemoveSyncedMembershipParams{TenantID: in.TenantID, GroupID: id, UserID: in.UserID, ConnectionID: in.ConnectionID})
		if err != nil {
			return err
		}
		if n == 1 {
			if err := recordMembership(ctx, tx, in.Actor, in.TenantID, id, in.UserID, in.ConnectionID, in.Provider, "group.member_removed"); err != nil {
				return err
			}
		}
	}
	return nil
}

// recordMembership audits, in tx, a membership change sync made through
// connectionID, with its group event.
func recordMembership(ctx context.Context, tx pgx.Tx, actor audit.Actor, tenantID, groupID, userID, connectionID uuid.UUID, source, action string) error {
	meta := map[string]any{"user_id": userID, "connection_id": connectionID, "source": source}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, action, "group", groupID, meta)); err != nil {
		return err
	}
	return outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: groupID, Topic: "group.events", EventType: action,
		Payload: map[string]any{"group_id": groupID, "user_id": userID, "tenant_id": tenantID, "source": source}})
}

// groupValues returns the asserted groups as they are matched: trimmed, each
// once, without empty or overlong ones. The database compares them ignoring
// case.
func groupValues(groups []string) []string {
	seen := make(map[string]bool, len(groups))
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		v := strings.TrimSpace(g)
		if v == "" || len(v) > maxGroupValue || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
