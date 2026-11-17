package qeetai

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

	"github.com/qeetgroup/qeet-id-server/internal/platform/ai"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// stubResolver is a ProviderResolver that reports a fixed config source without
// touching a database, so handler gate/status tests run in memory.
type stubResolver struct{ source ConfigSource }

func (s stubResolver) Resolve(_ context.Context, _ uuid.UUID) (EffectiveConfig, error) {
	return EffectiveConfig{Source: s.source, Provider: "test", Model: "test-model"}, nil
}

func (s stubResolver) ProviderFor(_ context.Context, _ uuid.UUID) (ai.Provider, error) {
	return nil, nil
}

// stubStore is a minimal serviceStore implementation for handler tests that
// runs entirely in memory without a database. Fields control return values and
// track method invocations so tests can assert on what was or was not called.
type stubStore struct {
	getConvErr   error
	turnErr      error
	appendCalled bool
	turns        int // turns begun and not yet released
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
func (s *stubStore) BeginTurn(_ context.Context, _, _ uuid.UUID) (func(), error) {
	if s.turnErr != nil {
		return nil, s.turnErr
	}
	s.turns++
	return func() { s.turns-- }, nil
}

// newHandlerRequest builds a POST .../messages request with the chi URL param
// and the JWT principal injected into the request context, so the handler's
// requireOrganizationUser and parseConversationID helpers work without a real router.
func newHandlerRequest(organizationID, userID, convID uuid.UUID, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost,
		"/v1/qeetai/conversations/"+convID.String()+"/messages",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	// Inject chi URL params (parseConversationID calls chi.URLParam).
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("conversationID", convID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	// Inject JWT principal (requireOrganizationUser calls httpx.RequireOrganization/RequireUser).
	p := &httpx.Principal{OrganizationID: &organizationID, UserID: &userID}
	req = req.WithContext(httpx.WithPrincipal(req.Context(), p))

	return req
}

// TestStreamMessages_IDOROwnershipCheck checks that posting to another user's
// conversation returns 404 and writes no message.
func TestStreamMessages_IDOROwnershipCheck(t *testing.T) {
	organizationID := uuid.New()
	userA := uuid.New()
	convOwnedByUserB := uuid.New()

	// The store returns ErrNotFound: convOwnedByUserB is not owned by userA.
	svc := &stubStore{getConvErr: errs.ErrNotFound}

	h := &Handler{
		Service:  svc,
		Resolver: stubResolver{source: SourceOrganization},
	}

	req := newHandlerRequest(organizationID, userA, convOwnedByUserB, `{"message":"injected prompt"}`)
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
	organizationID := uuid.New()
	userID := uuid.New()
	convID := uuid.New()

	// GetConversation succeeds: the user owns the conversation.
	svc := &stubStore{getConvErr: nil}

	h := &Handler{
		Service:      svc,
		Orchestrator: nil, // nil — run will panic, but that proves we got past the gate
		Resolver:     stubResolver{source: SourceOrganization},
	}

	req := newHandlerRequest(organizationID, userID, convID, `{"message":"hello"}`)
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

// TestStreamMessages_OneTurnAtATime checks that a message to a conversation
// whose previous turn is still running is refused 409 before anything is
// stored, and that a turn that runs releases the conversation when it ends.
func TestStreamMessages_OneTurnAtATime(t *testing.T) {
	organizationID, userID, convID := uuid.New(), uuid.New(), uuid.New()
	busy := &stubStore{turnErr: errs.ErrQeetAITurnInProgress}
	h := &Handler{Service: busy, Resolver: stubResolver{source: SourceOrganization}}
	rr := httptest.NewRecorder()
	h.streamMessages(rr, newHandlerRequest(organizationID, userID, convID, `{"message":"again"}`))
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), errs.CodeQeetAITurnInProgress) {
		t.Errorf("a second turn: %d %s, want 409 %s", rr.Code, rr.Body.String(), errs.CodeQeetAITurnInProgress)
	}
	if busy.appendCalled {
		t.Error("a refused turn stored its message")
	}

	free := &stubStore{}
	h = &Handler{Service: free, Resolver: stubResolver{source: SourceOrganization}}
	func() {
		defer func() { _ = recover() }() // the nil Orchestrator panics once the turn has begun
		h.streamMessages(httptest.NewRecorder(), newHandlerRequest(organizationID, userID, convID, `{"message":"hello"}`))
	}()
	if free.turns != 0 {
		t.Errorf("%d turns still held after the request ended, want 0", free.turns)
	}
}
