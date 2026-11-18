//go:build integration

package user

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// suspendedPage reads the caller's suspended-accounts list at query.
func suspendedPage(t *testing.T, h http.Handler, query string) SuspendedPage {
	t.Helper()
	rec := dbtest.Do(t, h, http.MethodGet, "/users/suspended"+query, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list suspended accounts%s: status %d (%s)", query, rec.Code, rec.Body.String())
	}
	var page SuspendedPage
	dbtest.Decode(t, rec, &page)
	return page
}

// listed returns the suspended account with id on page, if it is there.
func listed(page SuspendedPage, id uuid.UUID) (SuspendedUser, bool) {
	i := slices.IndexFunc(page.Items, func(u SuspendedUser) bool { return u.ID == id })
	if i < 0 {
		return SuspendedUser{}, false
	}
	return page.Items[i], true
}

// TestSuspensionEndsSessionsAndIsReviewed checks that suspending a person ends
// their sessions and records it once, that the suspension is listed and
// reviewed, that the person can't reactivate themselves, and that another
// organization sees a suspension it doesn't manage without its details.
func TestSuspensionEndsSessionsAndIsReviewed(t *testing.T) {
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	target := dbtest.User(t, organization, organization)
	session(t, target.ID, organization, "")
	session(t, target.ID, nil, "")
	guest := dbtest.User(t, other, other, organization)
	exec(t, `UPDATE account.users SET status = 'suspended' WHERE id = $1`, guest.ID)
	exec(t, `UPDATE account.users SET suspension_reason = 'account_compromise', suspension_risk = 'high' WHERE id = $1`, guest.ID)
	h := testHandler(t, nil)
	as := dbtest.Serve(dbtest.Principal(admin.ID, organization), h.Mount)
	path := "/users/" + target.ID.String()

	for range 2 {
		rec := dbtest.Do(t, as, http.MethodPatch, path, map[string]any{"status": "suspended"})
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"suspended"`) {
			t.Fatalf("suspend: %d %s", rec.Code, rec.Body.String())
		}
	}
	if n := liveSessions(t, target.ID); n != 0 {
		t.Errorf("%d sessions are still live after the suspension", n)
	}
	if n := audited(t, organization, "user.suspended", target.ID); n != 1 {
		t.Errorf("suspending twice recorded %d user.suspended audit events, want 1", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM platform.outbox WHERE aggregate_id = $1 AND event_type = 'user.suspended'`, target.ID); n != 1 {
		t.Errorf("%d user.suspended events, want 1", n)
	}

	page := suspendedPage(t, as, "")
	got, ok := listed(page, target.ID)
	if !ok || !got.CanManage || got.Source != "manual" || got.Review != "pending" || got.SuspendedAt == nil {
		t.Errorf("the suspension is listed as %+v (listed %t), want a manual one pending review that the organization manages", got, ok)
	}
	if page.Summary.Manual != 1 || page.Summary.Pending != 1 {
		t.Errorf("summary %+v, want 1 manual suspension pending review", page.Summary)
	}
	if visitor, ok := listed(page, guest.ID); !ok || visitor.CanManage || visitor.Reason != "managed_elsewhere" || visitor.Source != "external" || visitor.Risk != "unknown" || visitor.SuspendedAt != nil {
		t.Errorf("another organization's suspension is listed as %+v (listed %t), want it without its reason, risk or time", visitor, ok)
	}
	if _, ok := listed(suspendedPage(t, as, "?source=policy"), target.ID); ok {
		t.Error("filtering by policy source lists a manual suspension")
	}
	if _, ok := listed(suspendedPage(t, as, "?q="+strings.Split(target.Email, "@")[0]), target.ID); !ok {
		t.Error("searching by the person's email doesn't find their suspension")
	}
	if rec := dbtest.Do(t, as, http.MethodGet, "/users/suspended?reason=bogus", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("filter by an unknown reason: %d, want 400", rec.Code)
	}

	review := map[string]any{"reason": "account_compromise", "risk": "high", "review": "reviewed"}
	if rec := dbtest.Do(t, as, http.MethodPut, path+"/suspension", review); rec.Code != http.StatusNoContent {
		t.Fatalf("review the suspension: %d %s", rec.Code, rec.Body.String())
	}
	if got, ok := listed(suspendedPage(t, as, "?risk=high&review=reviewed"), target.ID); !ok || got.Reason != "account_compromise" {
		t.Errorf("the reviewed suspension is listed as %+v (listed %t)", got, ok)
	}
	if rec := dbtest.Do(t, as, http.MethodPut, path+"/suspension", map[string]any{"reason": "bored", "risk": "high", "review": "reviewed"}); rec.Code != http.StatusBadRequest {
		t.Errorf("review with an unknown reason: %d, want 400", rec.Code)
	}

	asTarget := dbtest.Serve(dbtest.Principal(target.ID, organization), h.Mount)
	if rec := dbtest.Do(t, asTarget, http.MethodPatch, path, map[string]any{"status": "active"}); rec.Code != http.StatusForbidden {
		t.Errorf("the person lifting their own suspension: %d, want 403", rec.Code)
	}
	if rec := dbtest.Do(t, asTarget, http.MethodPost, path+"/reactivate", nil); rec.Code != http.StatusForbidden {
		t.Errorf("the person reactivating themselves: %d, want 403", rec.Code)
	}

	rec := dbtest.Do(t, as, http.MethodPost, path+"/reactivate", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"active"`) {
		t.Fatalf("reactivate: %d %s", rec.Code, rec.Body.String())
	}
	if n := audited(t, organization, "user.reactivated", target.ID); n != 1 {
		t.Errorf("%d user.reactivated audit events, want 1", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1 AND suspended_at IS NULL AND suspension_reason IS NULL`, target.ID); n != 1 {
		t.Error("reactivating kept the suspension's details")
	}
	if rec := dbtest.Do(t, as, http.MethodPost, path+"/reactivate", nil); rec.Code != http.StatusConflict {
		t.Errorf("reactivate an active account: %d, want 409", rec.Code)
	}
	if rec := dbtest.Do(t, as, http.MethodPut, path+"/suspension", review); rec.Code != http.StatusConflict {
		t.Errorf("review the suspension of an active account: %d, want 409", rec.Code)
	}
}

// TestSuspendedPagesFollowTheirOrder checks that paging the suspended list by
// its cursor reads every account once and in order: the newest suspension
// first, ties by id, then the accounts another organization manages, which
// carry no suspension time, by id.
func TestSuspendedPagesFollowTheirOrder(t *testing.T) {
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	at := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	type dated struct {
		id uuid.UUID
		at time.Time
	}
	var own []dated
	for _, when := range []time.Time{at, at.Add(time.Hour), at.Add(time.Hour)} {
		u := dbtest.User(t, organization, organization)
		// The suspension trigger stamps the time of any status change, so the
		// chosen time is written after it.
		exec(t, `UPDATE account.users SET status = 'suspended' WHERE id = $1`, u.ID)
		exec(t, `UPDATE account.users SET suspended_at = $2 WHERE id = $1`, u.ID, when)
		own = append(own, dated{u.ID, when})
	}
	var guests []uuid.UUID
	for range 2 {
		g := dbtest.User(t, other, other, organization)
		exec(t, `UPDATE account.users SET status = 'suspended' WHERE id = $1`, g.ID)
		guests = append(guests, g.ID)
	}
	slices.SortFunc(own, func(a, b dated) int {
		if c := b.at.Compare(a.at); c != 0 {
			return c
		}
		return strings.Compare(a.id.String(), b.id.String())
	})
	slices.SortFunc(guests, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	var want []uuid.UUID
	for _, d := range own {
		want = append(want, d.id)
	}
	want = append(want, guests...)

	as := dbtest.Serve(dbtest.Principal(admin.ID, organization), testHandler(t, nil).Mount)
	var got []uuid.UUID
	query := "?limit=2"
	for range len(want) + 1 {
		page := suspendedPage(t, as, query)
		for _, u := range page.Items {
			got = append(got, u.ID)
		}
		if page.NextCursor == "" {
			break
		}
		query = "?limit=2&cursor=" + url.QueryEscape(page.NextCursor)
	}
	if !slices.Equal(got, want) {
		t.Errorf("paged %v, want %v", got, want)
	}
}

// TestSuspendedSearchTakesWildcardsLiterally checks that _ and % in the
// suspended-accounts search match only themselves.
func TestSuspendedSearchTakesWildcardsLiterally(t *testing.T) {
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	names := map[string]uuid.UUID{}
	for _, name := range []string{"qa_b", "qaXb", "100%", "plain"} {
		u := dbtest.User(t, organization, organization)
		exec(t, `UPDATE account.users SET status = 'suspended', display_name = $2 WHERE id = $1`, u.ID, name)
		names[name] = u.ID
	}
	as := dbtest.Serve(dbtest.Principal(admin.ID, organization), testHandler(t, nil).Mount)
	for query, want := range map[string]string{"qa_b": "qa_b", "%": "100%"} {
		page := suspendedPage(t, as, "?q="+url.QueryEscape(query))
		if len(page.Items) != 1 || page.Items[0].ID != names[want] || page.Total != 1 {
			t.Errorf("search %q: %d accounts (total %d), want only %q", query, len(page.Items), page.Total, want)
		}
	}
}
