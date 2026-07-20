package copilot

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/platform/api/rest/errs"
	"github.com/qeetgroup/qeet-id-server/platform/api/rest/httpx"
)

// stubStore is a minimal serviceStore implementation for handler tests that
// runs entirely in memory without a database. Fields control return values and
// track method invocations so tests can assert on what was or was not called.
type stubStore struct {
	getConvErr   error
	appendCalled bool
}

func (s *stubStore) Pool() *pgxpool.Pool { return nil }

func (s *stubStore) CreateConversation(_ context.Context, _, _ uuid.UUID, _ CreateConversationInput) (*Conversation, error) {
	return nil, nil
}
func (s *stubStore) ListConversations(_ context.Context, _, _ uuid.UUID) ([]Conversation, error) {
	return nil, nil
}
func (s *stubStore) GetConversation(_ context.Context, _, _, _ uuid.UUID) (*Conversation, []Message, error) {
	return nil, nil, s.getConvErr
}
func (s *stubStore) PatchConversation(_ context.Context, _, _, _ uuid.UUID, _ PatchConversationInput) (*Conversation, error) {
	return nil, nil
}
func (s *stubStore) DeleteConversation(_ context.Context, _, _, _ uuid.UUID) error { return nil }
func (s *stubStore) AppendMessage(_ context.Context, _, _ uuid.UUID, _ string, _ json.RawMessage) (*Message, error) {
	s.appendCalled = true
	return nil, nil
}

// newHandlerRequest builds a POST .../messages request with the chi URL param
// and the JWT principal injected into the request context, so the handler's
// requireTenantUser and parseConversationID helpers work without a real router.
func newHandlerRequest(tenantID, userID, convID uuid.UUID, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost,
		"/v1/copilot/conversations/"+convID.String()+"/messages",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	// Inject chi URL params (parseConversationID calls chi.URLParam).
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("conversationID", convID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	// Inject JWT principal (requireTenantUser calls httpx.RequireTenant/RequireUser).
	p := &httpx.Principal{TenantID: &tenantID, UserID: &userID}
	req = req.WithContext(httpx.WithPrincipal(req.Context(), p))

	return req
}

// TestStreamMessages_IDOROwnershipCheck is the critical IDOR security test.
//
// Invariant: when user A calls POST .../conversations/{convID}/messages and
// convID belongs to user B (GetConversation returns ErrNotFound), the handler
// MUST return 404 and MUST NOT call AppendMessage — no row is written into B's
// conversation.
//
// This test directly exercises the ownership gate added to streamMessages,
// which verifies ownership BEFORE any write or SSE header is emitted.
func TestStreamMessages_IDOROwnershipCheck(t *testing.T) {
	tenantID := uuid.New()
	userA := uuid.New()
	convOwnedByUserB := uuid.New()

	// The store returns ErrNotFound: convOwnedByUserB is not owned by userA.
	svc := &stubStore{getConvErr: errs.ErrNotFound}

	h := &Handler{
		Service:    svc,
		Configured: true,
		Provider:   "test",
		Model:      "test-model",
	}

	req := newHandlerRequest(tenantID, userA, convOwnedByUserB, `{"message":"injected prompt"}`)
	rr := httptest.NewRecorder()

	h.streamMessages(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d (IDOR ownership check must return 404)", rr.Code, http.StatusNotFound)
	}
	if svc.appendCalled {
		t.Error("SECURITY: AppendMessage was called despite failed ownership check — IDOR prevention failed")
	}
}

// TestStreamMessages_AuthorizedUserCanStream verifies that the ownership gate
// does NOT block a user accessing their own conversation: GetConversation
// succeeds, and the handler proceeds past the gate (it will then fail when
// trying to stream from a nil Orchestrator, but the 404 is NOT returned).
func TestStreamMessages_AuthorizedUserCanStream(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	convID := uuid.New()

	// GetConversation succeeds: the user owns the conversation.
	svc := &stubStore{getConvErr: nil}

	h := &Handler{
		Service:      svc,
		Orchestrator: nil, // nil — run will panic, but that proves we got past the gate
		Configured:   true,
		Provider:     "test",
		Model:        "test-model",
	}

	req := newHandlerRequest(tenantID, userID, convID, `{"message":"hello"}`)
	rr := httptest.NewRecorder()

	// The handler will proceed past the ownership gate. With a nil Orchestrator
	// it will panic when trying to call Run — recover that and verify we did NOT
	// get a 404 from the ownership check.
	defer func() {
		r := recover()
		// A panic (nil dereference on Orchestrator) is expected and proves we
		// passed the ownership gate. Getting a 404 would be wrong.
		if r == nil && rr.Code == http.StatusNotFound {
			t.Error("authorized user received 404 from ownership check — false positive")
		}
	}()
	h.streamMessages(rr, req)
}
