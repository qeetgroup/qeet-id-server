package ldap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ldap/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/federation/provision"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ssosync"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// The scheduled sync reads each active connection's directory every
// SyncIntervalMinutes (changes since the last run; everyone once a day) and
// suspends the people it disabled or no longer lists. A run that fails, or
// whose answer looks incomplete, changes nothing.
const (
	DefaultSyncInterval = 15 // minutes
	MinSyncInterval     = 5
	MaxSyncInterval     = 60

	SyncJobInterval = time.Minute

	// Below MinSyncInterval, so a connection's runs never overlap.
	syncTimeout    = 4 * time.Minute
	syncSearchTime = 2 * time.Minute
	syncPageSize   = 500 // Active Directory answers at most 1000 a page
	maxSyncsPerRun = 25

	syncActorType = "ldap_sync"

	// ACCOUNTDISABLE in Active Directory's userAccountControl.
	accountDisableFlag = 2

	minPeopleToJudge = 10
	minLinkedToJudge = 4
)

const (
	attrUserAccountControl = "userAccountControl"
	attrUSNChanged         = "uSNChanged"
	attrModifyTimestamp    = "modifyTimestamp"
)

// SyncRun counts the connections one run of the sync job synced and failed.
type SyncRun struct {
	Synced, Failed int
}

// SyncDue syncs each connection whose sync is due, in every organization,
// claiming each so no two instances sync it at once. It returns only faults on
// this side: a directory's failure is recorded on its connection.
func (s *Service) SyncDue(ctx context.Context) (SyncRun, error) {
	ctx = postgres.AcrossOrganizations(ctx)
	due, err := s.q.DueLdapSyncs(ctx, maxSyncsPerRun)
	if err != nil {
		return SyncRun{}, err
	}
	var run SyncRun
	var faults []error
	for _, d := range due {
		if ctx.Err() != nil {
			break
		}
		claim, err := s.q.ClaimLdapSync(ctx, dbgen.ClaimLdapSyncParams(d))
		if errors.Is(err, pgx.ErrNoRows) {
			continue // another instance took it
		}
		if err != nil {
			faults = append(faults, err)
			continue
		}
		outcome, err := s.syncConnection(ctx, d.ID, d.OrganizationID, claim)
		if err != nil {
			faults = append(faults, fmt.Errorf("ldap sync of connection %s: %w", d.ID, err))
		}
		switch outcome {
		case syncSucceeded:
			run.Synced++
		case syncFailed:
			run.Failed++
		}
	}
	return run, errors.Join(faults...)
}

const (
	syncSkipped = iota
	syncSucceeded
	syncFailed
)

// syncConnection runs a claimed sync, records it, and tells the connection's
// managers when its syncs start failing and when they recover.
func (s *Service) syncConnection(ctx context.Context, id, organizationID uuid.UUID, claim dbgen.ClaimLdapSyncRow) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()
	c, err := s.getFull(ctx, id, organizationID)
	if err != nil {
		return syncFailed, err
	}
	if ok, err := s.gate.FeatureAllowed(ctx, organizationID, "ldap"); err != nil || !ok {
		return syncSkipped, err
	}
	started := time.Now()
	res, syncErr := s.sync(ctx, c, syncPass{full: claim.FullRun, cursor: claim.Cursor, previous: claim.SyncPeople, failing: claim.SyncFailing})
	s.recordSync(ctx, c, started, res, syncErr)
	ids := dbgen.FailLdapSyncParams{ID: id, OrganizationID: organizationID}
	if syncErr != nil {
		if err := s.q.FailLdapSync(ctx, ids); err != nil {
			return syncFailed, err
		}
		if !claim.SyncFailing {
			s.tellManagers(ctx, c, syncErr)
		}
		if reasonOf(syncErr) == "" {
			return syncFailed, syncErr
		}
		return syncFailed, nil
	}
	if err := s.q.FinishLdapSync(ctx, dbgen.FinishLdapSyncParams{
		Cursor: res.cursor, FullRun: res.full, People: int32(min(res.people, 1<<30)), // #nosec G115 -- bounded
		ID: id, OrganizationID: organizationID,
	}); err != nil {
		return syncFailed, err
	}
	if claim.SyncFailing {
		s.tellManagers(ctx, c, nil)
	}
	return syncSucceeded, nil
}

// syncPass is what a run reads, and how the runs before it went.
type syncPass struct {
	full     bool
	cursor   string
	previous *int32
	failing  bool
}

// syncResult is what a run found and changed.
type syncResult struct {
	full        bool
	people      int
	suspended   int
	reactivated int
	updated     int
	kept        int
	cursor      string // "": unchanged
}

// sync reads c's directory as pass says and applies what it found.
func (s *Service) sync(ctx context.Context, c *connFull, pass syncPass) (syncResult, error) {
	res := syncResult{full: pass.full}
	if err := s.checkTLSVerify(c.SkipTLSVerify); err != nil {
		return res, err
	}
	// Audited once per failing streak, not every run.
	transport := s.checkTransport(c.ServerURL, c.StartTLS)
	if transport != nil && !pass.failing {
		transport = s.requireTLS(ctx, c, "sync", audit.Actor{Type: syncActorType})
	}
	if transport != nil {
		return res, transport
	}
	filter, err := listFilter(c.UserFilter)
	if err != nil {
		return res, err
	}
	if !res.full {
		term, ok := cursorTerm(pass.cursor)
		if ok {
			filter = "(&" + filter + term + ")"
		} else {
			res.full = true
		}
	}
	mapped, err := s.mapper.SourceAttributes(ctx, c.OrganizationID, c.ID.String())
	if err != nil {
		return res, err
	}
	entries, err := s.searchPeople(ctx, c, filter, mapped)
	if err != nil {
		return res, err
	}
	people := readPeople(c, entries, mapped)
	res.people = len(people)
	res.cursor = nextCursor(pass.cursor, entries)
	rows, err := s.q.LdapLinkedPeople(ctx, dbgen.LdapLinkedPeopleParams{OrganizationID: c.OrganizationID, ConnectionID: c.ID})
	if err != nil {
		return res, err
	}
	plan := planSync(people, linkedAccounts(rows), res.full)
	if res.full {
		if err := judge(len(people), pass.previous, plan); err != nil {
			return res, err
		}
	}
	return res, s.apply(ctx, c, plan, &res)
}

// searchPeople returns the entries filter finds; a failure part of the way returns none.
func (s *Service) searchPeople(ctx context.Context, c *connFull, filter string, mapped []string) ([]*goldap.Entry, error) {
	conn, err := c.dial(ctx, s.egress, s.allowInsecureTLS)
	if err != nil {
		return nil, unreachable(err)
	}
	defer conn.Close()
	conn.SetTimeout(syncSearchTime)
	if err := conn.Bind(c.BindDN, c.BindPassword); err != nil {
		return nil, ErrServiceBindFailed.Wrap(err)
	}
	attributes := append([]string{c.EmailAttribute, c.NameAttribute, groupsAttr,
		attrUserAccountControl, attrUSNChanged, attrModifyTimestamp}, mapped...)
	req := goldap.NewSearchRequest(c.BaseDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 0,
		int(syncSearchTime.Seconds()), false, filter, attributes, nil)
	res, err := conn.SearchWithPaging(req, syncPageSize)
	if err != nil {
		return nil, ErrSyncSearchFailed.Wrap(err)
	}
	return res.Entries, nil
}

// listFilter makes the user filter list everyone: (uid=%s) becomes (uid=*).
func listFilter(userFilter string) (string, error) {
	if !strings.Contains(userFilter, "%s") {
		return "", ErrSyncFilterInvalid
	}
	filter := strings.ReplaceAll(userFilter, "%s", "*")
	if _, err := goldap.CompileFilter(filter); err != nil {
		return "", ErrSyncFilterInvalid
	}
	return filter, nil
}

var generalizedTime = regexp.MustCompile(`^\d{14}(\.\d{1,7})?Z$`)

// cursorTerm is the filter term for changes since cursor ("usn:<n>" or
// "ts:<generalized time>"); false when there is none to use.
func cursorTerm(cursor string) (string, bool) {
	kind, value, _ := strings.Cut(cursor, ":")
	switch kind {
	case "usn":
		n, err := strconv.ParseUint(value, 10, 63)
		if err != nil {
			return "", false
		}
		return fmt.Sprintf("(%s>=%d)", attrUSNChanged, n+1), true
	case "ts":
		if !generalizedTime.MatchString(value) {
			return "", false
		}
		return "(" + attrModifyTimestamp + ">=" + value + ")", true
	}
	return "", false
}

// nextCursor is the newest change mark among entries, of cursor's kind ("" keeps cursor).
// uSNChanged is preferred: Active Directory keeps modifyTimestamp less precisely.
func nextCursor(cursor string, entries []*goldap.Entry) string {
	kind, _, _ := strings.Cut(cursor, ":")
	var usn uint64
	var ts string
	for _, e := range entries {
		if n, err := strconv.ParseUint(e.GetAttributeValue(attrUSNChanged), 10, 63); err == nil && n > usn {
			usn = n
		}
		if t := e.GetAttributeValue(attrModifyTimestamp); generalizedTime.MatchString(t) && t > ts {
			ts = t
		}
	}
	next := ""
	switch {
	case usn > 0 && kind != "ts":
		next = "usn:" + strconv.FormatUint(usn, 10)
	case ts != "" && kind != "usn":
		next = "ts:" + ts
	}
	if next == "" || (kind != "" && !newer(next, cursor)) {
		return ""
	}
	return next
}

func newer(a, b string) bool {
	_, av, _ := strings.Cut(a, ":")
	_, bv, _ := strings.Cut(b, ":")
	an, aerr := strconv.ParseUint(av, 10, 63)
	bn, berr := strconv.ParseUint(bv, 10, 63)
	if aerr == nil && berr == nil {
		return an > bn
	}
	return av > bv
}

type dirPerson struct {
	dn       string
	key      string
	email    string
	name     string
	groups   []string
	disabled bool
	source   map[string]any
}

// dnKey normalises dn, so two spellings of one DN compare equal.
func dnKey(dn string) string {
	parsed, err := goldap.ParseDN(dn)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(dn))
	}
	return strings.ToLower(parsed.String())
}

func readPeople(c *connFull, entries []*goldap.Entry, mapped []string) []dirPerson {
	people := make([]dirPerson, 0, len(entries))
	for _, e := range entries {
		p := dirPerson{
			dn: e.DN, key: dnKey(e.DN),
			email:  strings.ToLower(strings.TrimSpace(e.GetAttributeValue(c.EmailAttribute))),
			name:   e.GetAttributeValue(c.NameAttribute),
			groups: e.GetAttributeValues(groupsAttr),
			source: map[string]any{},
		}
		if flags, err := strconv.ParseInt(e.GetAttributeValue(attrUserAccountControl), 10, 64); err == nil {
			p.disabled = flags&accountDisableFlag != 0
		}
		for _, attribute := range append([]string{c.EmailAttribute, c.NameAttribute, groupsAttr}, mapped...) {
			if values := e.GetAttributeValues(attribute); len(values) > 0 {
				p.source[attribute] = values
			}
		}
		people = append(people, p)
	}
	return people
}

type linkedAccount struct {
	userID           uuid.UUID
	dns              []string
	emails           []string
	status           string
	suspensionSource string
	owner            bool
}

func linkedAccounts(rows []dbgen.LdapLinkedPeopleRow) []linkedAccount {
	var accounts []linkedAccount
	for _, r := range rows {
		if n := len(accounts); n == 0 || accounts[n-1].userID != r.UserID {
			accounts = append(accounts, linkedAccount{userID: r.UserID, status: r.Status,
				suspensionSource: r.SuspensionSource, owner: r.Owner, emails: []string{strings.ToLower(r.Email)}})
		}
		a := &accounts[len(accounts)-1]
		a.dns = append(a.dns, dnKey(r.Subject))
		if r.LinkEmail != "" {
			a.emails = append(a.emails, strings.ToLower(r.LinkEmail))
		}
	}
	return accounts
}

const (
	syncSuspend    = "suspend"
	syncReactivate = "reactivate"
	syncRefresh    = "refresh"
	syncKeep       = "keep" // an owner is never suspended, as SCIM never suspends one
)

const (
	causeDisabled = "disabled_in_directory"
	causeRemoved  = "removed_from_directory"
)

type syncAction struct {
	account linkedAccount
	person  *dirPerson
	kind    string
	cause   string
}

// planSync decides what to do to each account. An entry matches by linked DN,
// else by an address only one entry has, as a sign-in adopts by address; only
// a full run lists everyone, so only it suspends the unlisted.
func planSync(people []dirPerson, accounts []linkedAccount, full bool) []syncAction {
	byDN := make(map[string]*dirPerson, len(people))
	byEmail := make(map[string]*dirPerson, len(people))
	shared := map[string]bool{}
	for i := range people {
		p := &people[i]
		byDN[p.key] = p
		if p.email == "" {
			continue
		}
		if _, taken := byEmail[p.email]; taken {
			shared[p.email] = true
		}
		byEmail[p.email] = p
	}
	find := func(a linkedAccount) *dirPerson {
		for _, dn := range a.dns {
			if p := byDN[dn]; p != nil {
				return p
			}
		}
		for _, email := range a.emails {
			if p := byEmail[email]; p != nil && !shared[email] {
				return p
			}
		}
		return nil
	}
	var plan []syncAction
	for _, a := range accounts {
		p := find(a)
		suspended := a.status == "suspended"
		switch {
		case p == nil && !full:
		case p == nil || p.disabled:
			if suspended {
				continue
			}
			cause, kind := causeRemoved, syncSuspend
			if p != nil {
				cause = causeDisabled
			}
			if a.owner {
				kind = syncKeep
			}
			plan = append(plan, syncAction{account: a, person: p, kind: kind, cause: cause})
		case suspended && a.suspensionSource == "ldap":
			plan = append(plan, syncAction{account: a, person: p, kind: syncReactivate})
		case !suspended:
			plan = append(plan, syncAction{account: a, person: p, kind: syncRefresh})
		}
	}
	return plan
}

// judge refuses a full run whose answer looks incomplete, as a wrong base DN,
// filter or service account gives: nobody, under half the last run, or most
// accounts gone at once.
func judge(found int, previous *int32, plan []syncAction) error {
	active, gone := 0, 0
	for _, a := range plan {
		if a.kind == syncReactivate {
			continue
		}
		active++
		if a.cause == causeRemoved {
			gone++
		}
	}
	switch {
	case found == 0 && (active > 0 || (previous != nil && *previous > 0)):
		return ErrSyncEmptyResult
	case previous != nil && *previous >= minPeopleToJudge && found*2 < int(*previous):
		return ErrSyncPeopleDropped
	case active >= minLinkedToJudge && gone*2 > active:
		return ErrSyncPeopleDropped
	}
	return nil
}

// apply carries out plan, suspensions first, an account per transaction, and
// returns the first failure.
func (s *Service) apply(ctx context.Context, c *connFull, plan []syncAction, res *syncResult) error {
	var first error
	for _, pass := range [][]string{{syncSuspend, syncKeep}, {syncReactivate, syncRefresh}} {
		for _, a := range plan {
			if a.kind != pass[0] && a.kind != pass[1] {
				continue
			}
			started := time.Now()
			change, err := s.applyOne(ctx, c, a)
			if err != nil && first == nil {
				first = err
			}
			switch {
			case err != nil:
			case change == "suspended":
				res.suspended++
			case change == "reactivated":
				res.reactivated++
			case change == "updated":
				res.updated++
			case change == "kept":
				res.kept++
			}
			if change != "" || err != nil {
				s.recordPerson(ctx, c, a, change, started, err)
			}
		}
	}
	return first
}

// applyOne carries out a and says what changed ("" for nothing).
func (s *Service) applyOne(ctx context.Context, c *connFull, a syncAction) (string, error) {
	if a.kind == syncKeep {
		return "kept", nil
	}
	actor := audit.Actor{Type: syncActorType}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	change := ""
	switch a.kind {
	case syncSuspend:
		suspended, err := provision.SuspendForDirectory(ctx, tx, s.signals, c.OrganizationID, a.account.userID, provider)
		if err != nil || !suspended {
			return "", err
		}
		if err := recordAccount(ctx, tx, actor, c, a.account.userID, "user.suspended", a.cause); err != nil {
			return "", err
		}
		change = "suspended"
	case syncReactivate:
		n, err := s.q.WithTx(tx).ReactivateLdapSuspension(ctx, dbgen.ReactivateLdapSuspensionParams{ID: a.account.userID, OrganizationID: c.OrganizationID})
		if err != nil || n == 0 {
			return "", err
		}
		if _, err := authentication.EndSignIns(ctx, tx, s.signals, a.account.userID, sessionsignal.ReasonReactivated); err != nil {
			return "", err
		}
		if err := recordAccount(ctx, tx, actor, c, a.account.userID, "user.reactivated", "enabled_in_directory"); err != nil {
			return "", err
		}
		change = "reactivated"
		fallthrough
	case syncRefresh:
		updated, err := s.refresh(ctx, tx, c, a, actor)
		if err != nil {
			return "", err
		}
		if updated && change == "" {
			change = "updated"
		}
	}
	return change, tx.Commit(ctx)
}

// refresh applies the entry's profile and groups. The address is left to
// sign-in, which proves the domain it moves to.
func (s *Service) refresh(ctx context.Context, tx pgx.Tx, c *connFull, a syncAction, actor audit.Actor) (bool, error) {
	p := a.person
	profile, err := s.mapper.MapProfile(ctx, c.OrganizationID, c.ID.String(), p.source, false)
	if err != nil {
		return false, err
	}
	name, groups := p.name, p.groups
	if mapped, ok := profile["display_name"].(string); ok {
		name = mapped
	}
	if mapped, ok := profile["groups"].([]string); ok {
		groups = mapped
	}
	changes, err := ssosync.Refresh(ctx, tx, ssosync.SignIn{
		OrganizationID: c.OrganizationID, UserID: a.account.userID, ConnectionID: c.ID, Provider: provider,
		DisplayName: name, Groups: groups, Actor: actor,
	})
	if err != nil {
		return false, err
	}
	if len(profile) > 0 {
		if err := s.mapper.StoreProfile(ctx, tx, c.OrganizationID, a.account.userID, c.ID.String(), profile); err != nil {
			return false, err
		}
	}
	return changes.Any(), nil
}

// recordAccount audits the sync's change of an account and enqueues its event.
func recordAccount(ctx context.Context, tx pgx.Tx, actor audit.Actor, c *connFull, userID uuid.UUID, action, cause string) error {
	meta := map[string]any{"connection_id": c.ID, "source": provider, "cause": cause}
	if err := audit.Record(ctx, tx, actor.Event(c.OrganizationID, action, "user", userID, meta)); err != nil {
		return err
	}
	return outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: userID, Topic: "user.events", EventType: action,
		Payload: map[string]any{"organization_id": c.OrganizationID, "user_id": userID, "source": provider, "cause": cause}})
}

// recordPerson records what the sync did to one person in the directory's activity.
func (s *Service) recordPerson(ctx context.Context, c *connFull, a syncAction, change string, started time.Time, err error) {
	status := operationStatus("sync", err)
	if change == "kept" {
		status = keptStatus
	}
	params := map[string]string{"change": change}
	if a.cause != "" {
		params["cause"] = a.cause
	}
	subject := ""
	if a.person != nil {
		subject = a.person.dn
	}
	userID := a.account.userID
	s.observe(ctx, Operation{
		OrganizationID: c.OrganizationID, ConnectionID: c.ID, Operation: "sync", Resource: "user",
		Status: status, Started: started, Duration: time.Since(started), Reason: reasonOf(err),
		Params: params, Subject: subject, UserID: &userID,
	})
}

const keptStatus = http.StatusConflict

// recordSync records a run in the directory's activity.
func (s *Service) recordSync(ctx context.Context, c *connFull, started time.Time, res syncResult, err error) {
	mode := "incremental"
	if res.full {
		mode = "full"
	}
	params := map[string]string{
		"mode": mode, "people": strconv.Itoa(res.people), "suspended": strconv.Itoa(res.suspended),
		"reactivated": strconv.Itoa(res.reactivated), "updated": strconv.Itoa(res.updated), "kept": strconv.Itoa(res.kept),
	}
	if host := hostOnly(c.ServerURL); host != "" {
		params["host"] = host
	}
	s.observe(ctx, Operation{
		OrganizationID: c.OrganizationID, ConnectionID: c.ID, Operation: "sync", Resource: "connection",
		Status: operationStatus("sync", err), Started: started, Duration: time.Since(started),
		Reason: reasonOf(err), Params: params,
	})
}

// reasonOf is err's code, "" for none or an internal one.
func reasonOf(err error) string {
	if e := errs.As(err); e != nil && e.Code != errs.CodeInternal {
		return e.Code
	}
	return ""
}

// tellManagers tells the connection's managers in the app that its syncs
// fail (syncErr) or work again (nil).
func (s *Service) tellManagers(ctx context.Context, c *connFull, syncErr error) {
	ctx = context.WithoutCancel(ctx)
	managers, err := s.q.LdapConnectionManagers(ctx, c.OrganizationID)
	if err != nil {
		slog.Warn("ldap sync: list the connection's managers", "organization_id", c.OrganizationID, "connection_id", c.ID, "err", err)
		return
	}
	kind, title, href := "info", "Directory sync working again", "/directory"
	description := fmt.Sprintf("%s syncs with your directory again.", c.Name)
	if syncErr != nil {
		kind, title, href = "alert", "Directory sync failed", "/directory/sync-errors"
		why := "Something went wrong on our side."
		if e := errs.As(syncErr); e != nil && e.Code != errs.CodeInternal {
			why = e.Message
		}
		description = fmt.Sprintf("%s couldn't sync with your directory: %s Until it does, people removed or disabled there keep their access. Qeet ID tries again every %d minutes.",
			c.Name, why, c.SyncIntervalMinutes)
	}
	for _, userID := range managers {
		if err := s.notifier.Notify(ctx, c.OrganizationID, userID, kind, title, description, href); err != nil {
			slog.Warn("ldap sync: notify a connection manager", "organization_id", c.OrganizationID, "connection_id", c.ID, "err", err)
		}
	}
}
