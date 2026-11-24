// Package ssosync keeps an account in step with what each connection sign-in (SAML, LDAP, OIDC), or
// the scheduled LDAP sync, asserts: the mapped profile and its groups. It changes only memberships
// that connection's sign-ins made (never an administrator's, an import's or SCIM's) and never reaches
// a group holding the owner role or an administrative permission. Every change is audited in the
// sign-in's transaction.
package ssosync

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/identitylink"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ssosync/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
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
	OrganizationID uuid.UUID
	UserID         uuid.UUID
	ConnectionID   uuid.UUID
	Provider       string // "saml", "ldap" or "oidc": who the audit records name
	DisplayName    string // "" when none was asserted
	Email          string // the asserted address
	EmailManaged   bool   // Email is on a domain the organization manages
	Groups         []string
	GroupsWithheld bool
	Actor          audit.Actor
}

// Apply refreshes the account's profile and groups from in, within the
// sign-in's transaction tx.
func Apply(ctx context.Context, tx pgx.Tx, in SignIn) error {
	_, err := Refresh(ctx, tx, in)
	return err
}

// Changes are what Refresh changed on an account.
type Changes struct {
	Profile       bool
	GroupsAdded   int
	GroupsRemoved int
}

// Any reports whether anything changed.
func (c Changes) Any() bool { return c.Profile || c.GroupsAdded+c.GroupsRemoved > 0 }

// Refresh is Apply, reporting what it changed.
func Refresh(ctx context.Context, tx pgx.Tx, in SignIn) (Changes, error) {
	var c Changes
	var err error
	if c.Profile, err = refreshProfile(ctx, tx, in); err != nil {
		return c, err
	}
	c.GroupsAdded, c.GroupsRemoved, err = syncGroups(ctx, tx, in)
	return c, err
}

// refreshProfile sets the asserted display name, and the asserted address when
// refreshEmail allows it, recording what changed.
func refreshProfile(ctx context.Context, tx pgx.Tx, in SignIn) (bool, error) {
	q := dbgen.New(tx)
	current, err := q.GetAccountProfile(ctx, dbgen.GetAccountProfileParams{ID: in.UserID, OrganizationID: in.OrganizationID})
	if err != nil {
		return false, err
	}
	changed := map[string]any{}
	name := DisplayName(in.DisplayName)
	if name != "" && (current.DisplayName == nil || *current.DisplayName != name) {
		if err := q.SetDisplayName(ctx, dbgen.SetDisplayNameParams{DisplayName: &name, ID: in.UserID, OrganizationID: in.OrganizationID}); err != nil {
			return false, err
		}
		changed["display_name_changed"] = true
	}
	emailChanged, err := refreshEmail(ctx, tx, in, current.Email)
	if err != nil {
		return false, err
	}
	if emailChanged {
		changed["email_changed"] = true
	}
	if len(changed) == 0 {
		return false, nil
	}
	changed["connection_id"] = in.ConnectionID
	changed["source"] = in.Provider
	return true, audit.Record(ctx, tx, in.Actor.Event(in.OrganizationID, "user.updated", "user", in.UserID, changed))
}

// DisplayName is name as a sign-in sets it on an account: trimmed, or "" when
// it is longer than an account's display name may be.
func DisplayName(name string) string {
	name = strings.TrimSpace(name)
	if utf8.RuneCountInString(name) > maxDisplayName {
		return ""
	}
	return name
}

// refreshEmail moves the account to the asserted address under the adoption rules: on a domain the
// organization manages, not another account's, and not for an account that administers the
// organization, or the connection could take over an administrator's recovery. Recovery links sent to
// the old address stop working.
func refreshEmail(ctx context.Context, tx pgx.Tx, in SignIn, current string) (bool, error) {
	email := strings.ToLower(strings.TrimSpace(in.Email))
	if email == "" || !in.EmailManaged || strings.EqualFold(email, current) {
		return false, nil
	}
	admin, err := identitylink.Administers(ctx, tx, in.UserID, in.OrganizationID)
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
	if err := authentication.ExpireRecoveryLinks(ctx, savepoint, in.UserID); err != nil {
		return false, err
	}
	if err := dbgen.New(savepoint).SetEmail(ctx, dbgen.SetEmailParams{Email: email, ID: in.UserID, OrganizationID: in.OrganizationID}); err != nil {
		if postgres.IsUnique(err) {
			return false, nil
		}
		return false, err
	}
	return true, savepoint.Commit(ctx)
}

// syncGroups adds the person to the groups the asserted groups reach and takes
// them out of those the connection's sign-ins put them in that they no longer
// reach, recording each change with its event.
func syncGroups(ctx context.Context, tx pgx.Tx, in SignIn) (added, removed int, err error) {
	if in.GroupsWithheld {
		return 0, 0, nil
	}
	q := dbgen.New(tx)
	var targets []uuid.UUID
	if values := groupValues(in.Groups); len(values) > 0 {
		targets, err = q.SyncTargets(ctx, dbgen.SyncTargetsParams{
			OrganizationID: in.OrganizationID, ConnectionID: in.ConnectionID,
			MemberPermissions: identitylink.MemberPermissions(), IdpGroups: values,
		})
		if err != nil {
			return 0, 0, err
		}
	}
	current, err := q.SyncedMemberships(ctx, dbgen.SyncedMembershipsParams{OrganizationID: in.OrganizationID, UserID: in.UserID, ConnectionID: in.ConnectionID})
	if err != nil {
		return 0, 0, err
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
		n, err := q.AddSyncedMembership(ctx, dbgen.AddSyncedMembershipParams{GroupID: id, UserID: in.UserID, OrganizationID: in.OrganizationID, ConnectionID: in.ConnectionID})
		if err != nil {
			return added, removed, err
		}
		if n == 1 {
			added++
			if err := recordMembership(ctx, tx, in.Actor, in.OrganizationID, id, in.UserID, in.ConnectionID, in.Provider, "group.member_added"); err != nil {
				return added, removed, err
			}
		}
	}
	for _, id := range current {
		if wanted[id] {
			continue
		}
		n, err := q.RemoveSyncedMembership(ctx, dbgen.RemoveSyncedMembershipParams{OrganizationID: in.OrganizationID, GroupID: id, UserID: in.UserID, ConnectionID: in.ConnectionID})
		if err != nil {
			return added, removed, err
		}
		if n == 1 {
			removed++
			if err := recordMembership(ctx, tx, in.Actor, in.OrganizationID, id, in.UserID, in.ConnectionID, in.Provider, "group.member_removed"); err != nil {
				return added, removed, err
			}
		}
	}
	return added, removed, nil
}

// recordMembership audits, in tx, a membership change sync made through
// connectionID, with its group event.
func recordMembership(ctx context.Context, tx pgx.Tx, actor audit.Actor, organizationID, groupID, userID, connectionID uuid.UUID, source, action string) error {
	meta := map[string]any{"user_id": userID, "connection_id": connectionID, "source": source}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, action, "group", groupID, meta)); err != nil {
		return err
	}
	return outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: groupID, Topic: "group.events", EventType: action,
		Payload: map[string]any{"group_id": groupID, "user_id": userID, "organization_id": organizationID, "source": source}})
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
