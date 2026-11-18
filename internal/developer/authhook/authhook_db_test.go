//go:build integration

package authhook

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/requestsig"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// policyServer is a fake sign-in hook: it checks each call's signature against
// secret, and against old while that is set, as a receiver does (the shared
// request signer's Verify), and answers with status and reply.
type policyServer struct {
	*httptest.Server
	mu       sync.Mutex
	secret   string
	old      string
	status   int
	reply    string
	calls    int
	badSigns int
	oldSigns int
	last     map[string]any
}

// newPolicyServer starts a hook that allows every sign-in until t ends.
func newPolicyServer(t *testing.T, secret string) *policyServer {
	p := &policyServer{secret: secret, status: http.StatusOK, reply: `{"decision":"allow"}`}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		p.mu.Lock()
		defer p.mu.Unlock()
		p.calls++
		if requestsig.Verify(r.Header, body, p.secret, time.Now(), requestsig.Tolerance) != nil {
			p.badSigns++
		}
		if p.old != "" && requestsig.Verify(r.Header, body, p.old, time.Now(), requestsig.Tolerance) == nil {
			p.oldSigns++
		}
		p.last = nil
		_ = json.Unmarshal(body, &p.last)
		w.WriteHeader(p.status)
		_, _ = io.WriteString(w, p.reply)
	}))
	t.Cleanup(p.Close)
	return p
}

// answer makes the hook answer the next calls with status and reply.
func (p *policyServer) answer(status int, reply string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.status, p.reply = status, reply
}

// hookService returns the hook service, allowed to call loopback hooks.
func hookService(t *testing.T) *Service {
	t.Helper()
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(dbtest.Pool(t), egress.DevelopmentPolicy())
	svc.SetCipher(box)
	return svc
}

// skips counts the organization's auth_hook.skipped audit events.
func skips(t *testing.T, organizationID uuid.UUID) int {
	t.Helper()
	var n int
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `
		SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'auth_hook.skipped'
	`, organizationID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
