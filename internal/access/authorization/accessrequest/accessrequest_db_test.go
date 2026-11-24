//go:build integration

package accessrequest

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// roleService returns the role service over repo with no plan limit, no seat
// limit, no webhook events and no session announcements.
func roleService(t *testing.T, repo *rbac.Repository) *rbac.Service {
	t.Helper()
	svc, err := rbac.NewService(repo, rbac.ServiceDeps{
		Emitter: func(context.Context, uuid.UUID, string, any) error { return nil },
		Limits:  unlimited{}, Seats: unlimited{}, Signals: sessionsignal.New(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// unlimited is a plan with no limit on anything.
type unlimited struct{}

func (unlimited) Limit(context.Context, uuid.UUID, string) (int, error) { return -1, nil }
func (unlimited) SeatLimit(context.Context, uuid.UUID) (int, error)     { return -1, nil }
func (unlimited) WithinSeats(_ context.Context, _ pgx.Tx, _ uuid.UUID, _ int, change func() error) error {
	return change()
}

// inbox records the in-app notifications sent.
type inbox struct {
	mu   sync.Mutex
	sent map[uuid.UUID][]string
}

func (i *inbox) Notify(_ context.Context, _, userID uuid.UUID, _, title, _, _ string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.sent == nil {
		i.sent = map[uuid.UUID][]string{}
	}
	i.sent[userID] = append(i.sent[userID], title)
	return nil
}

func (i *inbox) count(id uuid.UUID) int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return len(i.sent[id])
}

// phones records the phone notifications sent.
type phones struct {
	mu   sync.Mutex
	sent []uuid.UUID
}

func (p *phones) NotifyPhones(_ context.Context, userID uuid.UUID, _, _ string, _ map[string]string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sent = append(p.sent, userID)
}

type world struct {
	svc          *Service
	inbox        *inbox
	phones       *phones
	organization uuid.UUID
	requester    uuid.UUID
	approver     uuid.UUID
	finance      uuid.UUID
}

func setup(t *testing.T) world {
	t.Helper()
	pool := dbtest.Pool(t)
	repo := rbac.NewRepository(pool)
	w := world{inbox: &inbox{}, phones: &phones{}}
	svc, err := NewService(pool, roleService(t, repo), repo, w.inbox, w.phones)
	if err != nil {
		t.Fatal(err)
	}
	w.svc = svc
	w.organization = dbtest.Organization(t)
	w.requester = dbtest.User(t, w.organization, w.organization).ID
	w.approver = dbtest.User(t, w.organization).ID
	dbtest.Assign(t, w.approver, w.organization, dbtest.Role(t, w.organization, "role.write", "role.read", "user.read"))
	w.finance = dbtest.Role(t, w.organization, "user.read")
	return w
}

func holds(t *testing.T, user, organization, role uuid.UUID) bool {
	t.Helper()
	return dbtest.Count(t, `SELECT COUNT(*) FROM rbac.user_roles WHERE user_id = $1 AND organization_id = $2 AND role_id = $3`, user, organization, role) == 1
}

func hours(n int) *int { return &n }

// TestApprovedAccessIsGivenAndTakenBack follows a time-limited request from
// asking to the sweep that ends it.
func TestApprovedAccessIsGivenAndTakenBack(t *testing.T) {
	ctx := dbtest.Context(t)
	w := setup(t)
	user := audit.Actor{Type: "user", UserID: &w.requester}

	req, err := w.svc.Create(ctx, w.organization, w.requester, CreateInput{RoleID: w.finance, Reason: "  Closing the quarter  ", DurationHours: hours(8)}, user)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if req.Status != StatusPending || req.Reason != "Closing the quarter" || req.DurationHours == nil || *req.DurationHours != 8 {
		t.Fatalf("created %+v", req)
	}
	if w.inbox.count(w.approver) != 1 || len(w.phones.sent) != 1 || w.phones.sent[0] != w.approver {
		t.Errorf("the approver was told %d times in the app and on phones %v", w.inbox.count(w.approver), w.phones.sent)
	}
	if w.inbox.count(w.requester) != 0 {
		t.Error("the requester was told about their own request")
	}
	if _, err := w.svc.Create(ctx, w.organization, w.requester, CreateInput{RoleID: w.finance, Reason: "again"}, user); !errors.Is(err, ErrPending) {
		t.Errorf("a second request for the same role: %v, want %v", err, ErrPending)
	}

	if _, err := w.svc.Approve(ctx, w.organization, req.ID, w.requester, "", user); !errors.Is(err, ErrOwn) {
		t.Errorf("approving one's own request: %v, want %v", err, ErrOwn)
	}
	approver := audit.Actor{Type: "user", UserID: &w.approver}
	got, err := w.svc.Approve(ctx, w.organization, req.ID, w.approver, "Until Ravi is back", approver)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if got.Status != StatusApproved || got.AccessEndsAt == nil || got.DecidedBy == nil || got.DecidedBy.ID != w.approver || got.DecisionNote != "Until Ravi is back" {
		t.Fatalf("approved %+v", got)
	}
	if !holds(t, w.requester, w.organization, w.finance) {
		t.Fatal("approving didn't give the role")
	}
	if _, err := w.svc.Approve(ctx, w.organization, req.ID, w.approver, "", approver); !errors.Is(err, ErrClosed) {
		t.Errorf("approving twice: %v, want %v", err, ErrClosed)
	}

	// Its time is up: the sweep takes the role back, once.
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE rbac.access_requests SET access_ends_at = NOW() - interval '1 minute' WHERE id = $1`, req.ID); err != nil {
		t.Fatal(err)
	}
	res, err := w.svc.Sweep(ctx)
	if err != nil || res.Ended != 1 || res.Failed != 0 {
		t.Fatalf("sweep: %+v %v", res, err)
	}
	if holds(t, w.requester, w.organization, w.finance) {
		t.Error("the ended grant still holds the role")
	}
	ended, _ := w.svc.Get(ctx, w.organization, req.ID)
	if ended.EndedAt == nil {
		t.Error("the ended grant isn't marked ended")
	}
	if res, _ := w.svc.Sweep(ctx); res.Ended != 0 {
		t.Errorf("the sweep ended it again: %+v", res)
	}
}

// TestARoleAlreadyHeldIsNeverTakenBack checks a request approved for a role
// the requester was meanwhile given directly leaves that role alone.
func TestARoleAlreadyHeldIsNeverTakenBack(t *testing.T) {
	ctx := dbtest.Context(t)
	w := setup(t)
	req, err := w.svc.Create(ctx, w.organization, w.requester, CreateInput{RoleID: w.finance, Reason: "Payments", DurationHours: hours(1)}, audit.Actor{})
	if err != nil {
		t.Fatal(err)
	}
	dbtest.Assign(t, w.requester, w.organization, w.finance)
	got, err := w.svc.Approve(ctx, w.organization, req.ID, w.approver, "", audit.Actor{Type: "user", UserID: &w.approver})
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessEndsAt != nil {
		t.Errorf("a role already held got an end: %v", got.AccessEndsAt)
	}
	if res, _ := w.svc.Sweep(ctx); res.Ended != 0 || !holds(t, w.requester, w.organization, w.finance) {
		t.Errorf("the sweep took back a role the request didn't give: %+v", res)
	}
	if _, err := w.svc.Create(ctx, w.organization, w.requester, CreateInput{RoleID: w.finance, Reason: "more"}, audit.Actor{}); !errors.Is(err, ErrRoleHeld) {
		t.Errorf("asking for a role held: %v, want %v", err, ErrRoleHeld)
	}
}

// TestPermanentGrantSurvivesTheAccessRequestSweep checks that a role given for
// a time by a request, then given outright by an administrator, is not taken
// back when the request's time is up.
func TestPermanentGrantSurvivesTheAccessRequestSweep(t *testing.T) {
	ctx := dbtest.Context(t)
	w := setup(t)
	approver := audit.Actor{Type: "user", UserID: &w.approver}
	req, err := w.svc.Create(ctx, w.organization, w.requester, CreateInput{RoleID: w.finance, Reason: "Quarter close", DurationHours: hours(8)}, audit.Actor{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.Approve(ctx, w.organization, req.ID, w.approver, "", approver); err != nil {
		t.Fatal(err)
	}
	// The administrator then gives the role for good.
	if err := roleService(t, rbac.NewRepository(dbtest.Pool(t))).AssignRole(ctx, w.requester, w.organization, w.finance, &w.approver, approver); err != nil {
		t.Fatal(err)
	}
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE rbac.access_requests SET access_ends_at = NOW() - interval '1 minute' WHERE id = $1 AND access_ends_at IS NOT NULL`, req.ID); err != nil {
		t.Fatal(err)
	}
	if res, err := w.svc.Sweep(ctx); err != nil || res.Ended != 0 {
		t.Errorf("sweep: %+v, %v; want nothing ended", res, err)
	}
	if !holds(t, w.requester, w.organization, w.finance) {
		t.Error("the sweep took back a role given for good since")
	}
}

// TestDenyCancelAndLapse covers the other answers.
func TestDenyCancelAndLapse(t *testing.T) {
	ctx := dbtest.Context(t)
	w := setup(t)
	approver := audit.Actor{Type: "user", UserID: &w.approver}

	denied, _ := w.svc.Create(ctx, w.organization, w.requester, CreateInput{RoleID: w.finance, Reason: "Payments"}, audit.Actor{})
	if _, err := w.svc.Deny(ctx, w.organization, denied.ID, w.approver, "  ", approver); !errors.Is(err, ErrNoteNeeded) {
		t.Errorf("denying without a note: %v, want %v", err, ErrNoteNeeded)
	}
	got, err := w.svc.Deny(ctx, w.organization, denied.ID, w.approver, "Ask Ravi", approver)
	if err != nil || got.Status != StatusDenied || got.DecisionNote != "Ask Ravi" || holds(t, w.requester, w.organization, w.finance) {
		t.Fatalf("deny: %+v %v", got, err)
	}
	if w.inbox.count(w.requester) != 1 {
		t.Error("the requester wasn't told it was denied")
	}

	other := dbtest.Role(t, w.organization, "user.read")
	cancelled, _ := w.svc.Create(ctx, w.organization, w.requester, CreateInput{RoleID: other, Reason: "Reports"}, audit.Actor{})
	if err := w.svc.Cancel(ctx, w.organization, w.approver, cancelled.ID, approver); !errors.Is(err, errs.ErrNotFound) {
		t.Errorf("cancelling someone else's request: %v, want %v", err, errs.ErrNotFound)
	}
	if err := w.svc.Cancel(ctx, w.organization, w.requester, cancelled.ID, audit.Actor{}); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if err := w.svc.Cancel(ctx, w.organization, w.requester, cancelled.ID, audit.Actor{}); !errors.Is(err, ErrClosed) {
		t.Errorf("cancelling twice: %v, want %v", err, ErrClosed)
	}

	third := dbtest.Role(t, w.organization, "user.read")
	lapsing, _ := w.svc.Create(ctx, w.organization, w.requester, CreateInput{RoleID: third, Reason: "Audit"}, audit.Actor{})
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE rbac.access_requests SET expires_at = NOW() - interval '1 minute' WHERE id = $1`, lapsing.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.Approve(ctx, w.organization, lapsing.ID, w.approver, "", approver); !errors.Is(err, ErrClosed) {
		t.Errorf("approving a lapsed request: %v, want %v", err, ErrClosed)
	}
	if res, err := w.svc.Sweep(ctx); err != nil || res.Lapsed != 1 {
		t.Fatalf("sweep: %+v %v", res, err)
	}
	if got, _ := w.svc.Get(ctx, w.organization, lapsing.ID); got.Status != StatusExpired {
		t.Errorf("lapsed request is %s", got.Status)
	}
}

// TestRequestsStayInTheirOrganization checks the owner role can't be asked
// for, and that another organization neither sees nor answers a request.
func TestRequestsStayInTheirOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	w := setup(t)
	var owner uuid.UUID
	if err := dbtest.Pool(t).QueryRow(ctx, `INSERT INTO rbac.roles (organization_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id`, w.organization).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.Create(ctx, w.organization, w.requester, CreateInput{RoleID: owner, Reason: "please"}, audit.Actor{}); !errors.Is(err, errs.ErrNotFound) {
		t.Errorf("asking for the owner role: %v, want %v", err, errs.ErrNotFound)
	}
	roles, err := w.svc.RequestableRoles(ctx, w.organization, w.requester)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range roles {
		if r.ID == owner {
			t.Error("the owner role is offered")
		}
	}

	req, _ := w.svc.Create(ctx, w.organization, w.requester, CreateInput{RoleID: w.finance, Reason: "Payments"}, audit.Actor{})
	elsewhere := dbtest.Organization(t)
	outsider := dbtest.User(t, elsewhere).ID
	dbtest.Assign(t, outsider, elsewhere, dbtest.Role(t, elsewhere, "role.write", "role.read"))

	h := &Handler{Service: w.svc, GrantCheck: func(context.Context, *httpx.Principal, uuid.UUID, uuid.UUID) error { return nil }}
	asOutsider := dbtest.Serve(dbtest.Principal(outsider, elsewhere), func(r chi.Router) { h.Mount(r) })
	if rec := dbtest.Do(t, asOutsider, http.MethodGet, "/organizations/"+elsewhere.String()+"/access-requests/"+req.ID.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organization reads the request: %d", rec.Code)
	}
	if rec := dbtest.Do(t, asOutsider, http.MethodPost, "/organizations/"+elsewhere.String()+"/access-requests/"+req.ID.String()+"/approve", nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organization approves the request: %d", rec.Code)
	}
	if rec := dbtest.Do(t, asOutsider, http.MethodGet, "/organizations/"+w.organization.String()+"/access-requests", nil); rec.Code != http.StatusForbidden {
		t.Errorf("another organization lists this one's requests by path: %d", rec.Code)
	}

	asApprover := dbtest.Serve(dbtest.Principal(w.approver, w.organization), func(r chi.Router) { h.Mount(r) })
	rec := dbtest.Do(t, asApprover, http.MethodPost, "/organizations/"+w.organization.String()+"/access-requests/"+req.ID.String()+"/approve", nil)
	if rec.Code != http.StatusOK || !holds(t, w.requester, w.organization, w.finance) {
		t.Errorf("approving with no body: %d %s", rec.Code, rec.Body.String())
	}
}
