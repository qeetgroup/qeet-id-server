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

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

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
	svc       *Service
	inbox     *inbox
	phones    *phones
	tenant    uuid.UUID
	requester uuid.UUID
	approver  uuid.UUID
	finance   uuid.UUID
}

func setup(t *testing.T) world {
	t.Helper()
	pool := dbtest.Pool(t)
	repo := rbac.NewRepository(pool)
	svc := NewService(pool, rbac.NewService(repo), repo)
	w := world{svc: svc, inbox: &inbox{}, phones: &phones{}}
	svc.SetNotifier(w.inbox)
	svc.SetPhoneNotifier(w.phones)
	w.tenant = dbtest.Tenant(t)
	w.requester = dbtest.User(t, w.tenant, w.tenant).ID
	w.approver = dbtest.User(t, w.tenant).ID
	dbtest.Assign(t, w.approver, w.tenant, dbtest.Role(t, w.tenant, "role.write", "role.read", "user.read"))
	w.finance = dbtest.Role(t, w.tenant, "user.read")
	return w
}

func holds(t *testing.T, user, tenant, role uuid.UUID) bool {
	t.Helper()
	return dbtest.Count(t, `SELECT COUNT(*) FROM rbac.user_roles WHERE user_id = $1 AND tenant_id = $2 AND role_id = $3`, user, tenant, role) == 1
}

func hours(n int) *int { return &n }

// TestApprovedAccessIsGivenAndTakenBack follows a time-limited request from
// asking to the sweep that ends it.
func TestApprovedAccessIsGivenAndTakenBack(t *testing.T) {
	ctx := dbtest.Context(t)
	w := setup(t)
	user := audit.Actor{Type: "user", UserID: &w.requester}

	req, err := w.svc.Create(ctx, w.tenant, w.requester, CreateInput{RoleID: w.finance, Reason: "  Closing the quarter  ", DurationHours: hours(8)}, user)
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
	if _, err := w.svc.Create(ctx, w.tenant, w.requester, CreateInput{RoleID: w.finance, Reason: "again"}, user); !errors.Is(err, errs.ErrAccessRequestPending) {
		t.Errorf("a second request for the same role: %v, want %v", err, errs.ErrAccessRequestPending)
	}

	if _, err := w.svc.Approve(ctx, w.tenant, req.ID, w.requester, "", user); !errors.Is(err, errs.ErrAccessRequestOwn) {
		t.Errorf("approving one's own request: %v, want %v", err, errs.ErrAccessRequestOwn)
	}
	approver := audit.Actor{Type: "user", UserID: &w.approver}
	got, err := w.svc.Approve(ctx, w.tenant, req.ID, w.approver, "Until Ravi is back", approver)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if got.Status != StatusApproved || got.AccessEndsAt == nil || got.DecidedBy == nil || got.DecidedBy.ID != w.approver || got.DecisionNote != "Until Ravi is back" {
		t.Fatalf("approved %+v", got)
	}
	if !holds(t, w.requester, w.tenant, w.finance) {
		t.Fatal("approving didn't give the role")
	}
	if _, err := w.svc.Approve(ctx, w.tenant, req.ID, w.approver, "", approver); !errors.Is(err, errs.ErrAccessRequestClosed) {
		t.Errorf("approving twice: %v, want %v", err, errs.ErrAccessRequestClosed)
	}

	// Its time is up: the sweep takes the role back, once.
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE rbac.access_requests SET access_ends_at = NOW() - interval '1 minute' WHERE id = $1`, req.ID); err != nil {
		t.Fatal(err)
	}
	res, err := w.svc.Sweep(ctx)
	if err != nil || res.Ended != 1 || res.Failed != 0 {
		t.Fatalf("sweep: %+v %v", res, err)
	}
	if holds(t, w.requester, w.tenant, w.finance) {
		t.Error("the ended grant still holds the role")
	}
	ended, _ := w.svc.Get(ctx, w.tenant, req.ID)
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
	req, err := w.svc.Create(ctx, w.tenant, w.requester, CreateInput{RoleID: w.finance, Reason: "Payments", DurationHours: hours(1)}, audit.Actor{})
	if err != nil {
		t.Fatal(err)
	}
	dbtest.Assign(t, w.requester, w.tenant, w.finance)
	got, err := w.svc.Approve(ctx, w.tenant, req.ID, w.approver, "", audit.Actor{Type: "user", UserID: &w.approver})
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessEndsAt != nil {
		t.Errorf("a role already held got an end: %v", got.AccessEndsAt)
	}
	if res, _ := w.svc.Sweep(ctx); res.Ended != 0 || !holds(t, w.requester, w.tenant, w.finance) {
		t.Errorf("the sweep took back a role the request didn't give: %+v", res)
	}
	if _, err := w.svc.Create(ctx, w.tenant, w.requester, CreateInput{RoleID: w.finance, Reason: "more"}, audit.Actor{}); !errors.Is(err, errs.ErrAccessRequestRoleHeld) {
		t.Errorf("asking for a role held: %v, want %v", err, errs.ErrAccessRequestRoleHeld)
	}
}

// TestDenyCancelAndLapse covers the other answers.
func TestDenyCancelAndLapse(t *testing.T) {
	ctx := dbtest.Context(t)
	w := setup(t)
	approver := audit.Actor{Type: "user", UserID: &w.approver}

	denied, _ := w.svc.Create(ctx, w.tenant, w.requester, CreateInput{RoleID: w.finance, Reason: "Payments"}, audit.Actor{})
	if _, err := w.svc.Deny(ctx, w.tenant, denied.ID, w.approver, "  ", approver); !errors.Is(err, errs.ErrAccessRequestNoteNeeded) {
		t.Errorf("denying without a note: %v, want %v", err, errs.ErrAccessRequestNoteNeeded)
	}
	got, err := w.svc.Deny(ctx, w.tenant, denied.ID, w.approver, "Ask Ravi", approver)
	if err != nil || got.Status != StatusDenied || got.DecisionNote != "Ask Ravi" || holds(t, w.requester, w.tenant, w.finance) {
		t.Fatalf("deny: %+v %v", got, err)
	}
	if w.inbox.count(w.requester) != 1 {
		t.Error("the requester wasn't told it was denied")
	}

	other := dbtest.Role(t, w.tenant, "user.read")
	cancelled, _ := w.svc.Create(ctx, w.tenant, w.requester, CreateInput{RoleID: other, Reason: "Reports"}, audit.Actor{})
	if err := w.svc.Cancel(ctx, w.tenant, w.approver, cancelled.ID, approver); !errors.Is(err, errs.ErrNotFound) {
		t.Errorf("cancelling someone else's request: %v, want %v", err, errs.ErrNotFound)
	}
	if err := w.svc.Cancel(ctx, w.tenant, w.requester, cancelled.ID, audit.Actor{}); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if err := w.svc.Cancel(ctx, w.tenant, w.requester, cancelled.ID, audit.Actor{}); !errors.Is(err, errs.ErrAccessRequestClosed) {
		t.Errorf("cancelling twice: %v, want %v", err, errs.ErrAccessRequestClosed)
	}

	third := dbtest.Role(t, w.tenant, "user.read")
	lapsing, _ := w.svc.Create(ctx, w.tenant, w.requester, CreateInput{RoleID: third, Reason: "Audit"}, audit.Actor{})
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE rbac.access_requests SET expires_at = NOW() - interval '1 minute' WHERE id = $1`, lapsing.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.Approve(ctx, w.tenant, lapsing.ID, w.approver, "", approver); !errors.Is(err, errs.ErrAccessRequestClosed) {
		t.Errorf("approving a lapsed request: %v, want %v", err, errs.ErrAccessRequestClosed)
	}
	if res, err := w.svc.Sweep(ctx); err != nil || res.Lapsed != 1 {
		t.Fatalf("sweep: %+v %v", res, err)
	}
	if got, _ := w.svc.Get(ctx, w.tenant, lapsing.ID); got.Status != StatusExpired {
		t.Errorf("lapsed request is %s", got.Status)
	}
}

// TestRequestsStayInTheirOrganisation checks the owner role can't be asked
// for, and that another organisation neither sees nor answers a request.
func TestRequestsStayInTheirOrganisation(t *testing.T) {
	ctx := dbtest.Context(t)
	w := setup(t)
	var owner uuid.UUID
	if err := dbtest.Pool(t).QueryRow(ctx, `INSERT INTO rbac.roles (tenant_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id`, w.tenant).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.Create(ctx, w.tenant, w.requester, CreateInput{RoleID: owner, Reason: "please"}, audit.Actor{}); !errors.Is(err, errs.ErrNotFound) {
		t.Errorf("asking for the owner role: %v, want %v", err, errs.ErrNotFound)
	}
	roles, err := w.svc.RequestableRoles(ctx, w.tenant, w.requester)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range roles {
		if r.ID == owner {
			t.Error("the owner role is offered")
		}
	}

	req, _ := w.svc.Create(ctx, w.tenant, w.requester, CreateInput{RoleID: w.finance, Reason: "Payments"}, audit.Actor{})
	elsewhere := dbtest.Tenant(t)
	outsider := dbtest.User(t, elsewhere).ID
	dbtest.Assign(t, outsider, elsewhere, dbtest.Role(t, elsewhere, "role.write", "role.read"))

	h := &Handler{Service: w.svc, GrantCheck: func(context.Context, *httpx.Principal, uuid.UUID, uuid.UUID) error { return nil }}
	asOutsider := dbtest.Serve(dbtest.Principal(outsider, elsewhere), func(r chi.Router) { h.Mount(r) })
	if rec := dbtest.Do(t, asOutsider, http.MethodGet, "/tenants/"+elsewhere.String()+"/access-requests/"+req.ID.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organisation reads the request: %d", rec.Code)
	}
	if rec := dbtest.Do(t, asOutsider, http.MethodPost, "/tenants/"+elsewhere.String()+"/access-requests/"+req.ID.String()+"/approve", nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organisation approves the request: %d", rec.Code)
	}
	if rec := dbtest.Do(t, asOutsider, http.MethodGet, "/tenants/"+w.tenant.String()+"/access-requests", nil); rec.Code != http.StatusForbidden {
		t.Errorf("another organisation lists this one's requests by path: %d", rec.Code)
	}

	asApprover := dbtest.Serve(dbtest.Principal(w.approver, w.tenant), func(r chi.Router) { h.Mount(r) })
	rec := dbtest.Do(t, asApprover, http.MethodPost, "/tenants/"+w.tenant.String()+"/access-requests/"+req.ID.String()+"/approve", nil)
	if rec.Code != http.StatusOK || !holds(t, w.requester, w.tenant, w.finance) {
		t.Errorf("approving with no body: %d %s", rec.Code, rec.Body.String())
	}
}
