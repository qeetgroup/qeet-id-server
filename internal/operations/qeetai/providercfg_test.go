package qeetai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/ai/openai"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// staticKey is a KeyProvider with a fixed data key.
type staticKey struct{}

func (staticKey) DataKey(context.Context) ([]byte, error) { return make([]byte, 32), nil }

// TestStreamClientOutlivesHeaderTimeout checks that a streamed reply may last
// longer than the stream client's header timeout, which a whole-request timeout
// of the same length cuts short, and that a provider sending no headers in time
// is cut off.
func TestStreamClientOutlivesHeaderTimeout(t *testing.T) {
	const headerTimeout = 500 * time.Millisecond
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stall" {
			select {
			case <-r.Context().Done():
			case <-time.After(4 * headerTimeout):
			}
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		for i := range 3 {
			_, _ = fmt.Fprintf(w, "data: %d\n\n", i)
			w.(http.Flusher).Flush()
			time.Sleep(headerTimeout)
		}
	}))
	defer srv.Close()
	policy := egress.DevelopmentPolicy()

	read := func(client *http.Client, path string) (string, error) {
		resp, err := client.Get(srv.URL + path)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		return string(body), err
	}
	if body, err := read(newStreamClient(policy, headerTimeout), "/stream"); err != nil || !strings.Contains(body, "data: 2") {
		t.Errorf("stream client: body %q, err %v; want the whole stream", body, err)
	}
	if _, err := read(policy.HTTPClient(headerTimeout), "/stream"); err == nil {
		t.Error("a whole-request timeout read the whole stream; the test no longer shows the difference")
	}
	if _, err := read(newStreamClient(policy, headerTimeout), "/stall"); err == nil {
		t.Error("stream client waited past its header timeout")
	}
}

// TestProviderConfigClients checks that model calls stream through a client
// with no whole-request timeout and that Test probes stay bounded.
func TestProviderConfigClients(t *testing.T) {
	c, err := NewProviderConfig(context.Background(), nil, staticKey{}, PlatformProvider{}, egress.DevelopmentPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if c.httpClient.Timeout != probeTimeout {
		t.Errorf("probe client timeout = %s, want %s", c.httpClient.Timeout, probeTimeout)
	}
	p, ok := c.buildProvider("openai", "key", "", "model", 16).(*openai.Client)
	if !ok {
		t.Fatal("buildProvider(openai) did not return an *openai.Client")
	}
	if p.HTTPClient != c.streamClient || p.HTTPClient.Timeout != 0 {
		t.Errorf("model calls use a client with timeout %s, want the stream client with none", p.HTTPClient.Timeout)
	}
	if tr, ok := c.streamClient.Transport.(*http.Transport); !ok || tr.ResponseHeaderTimeout != streamHeaderTimeout {
		t.Errorf("stream client transport %T has no %s response header timeout", c.streamClient.Transport, streamHeaderTimeout)
	}
}

// TestEvalProbeAnswers checks the code and status a Test probe answers with for
// each kind of provider response.
func TestEvalProbeAnswers(t *testing.T) {
	cases := []struct {
		provider   string
		status     int
		wantCode   string
		wantStatus int
	}{
		{"openai", http.StatusUnauthorized, errs.CodeQeetAIProviderKeyInvalid, http.StatusBadRequest},
		{"anthropic", http.StatusBadRequest, errs.CodeQeetAIProviderModelInvalid, http.StatusBadRequest},
		{"openai", http.StatusInternalServerError, errs.CodeQeetAIProviderError, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s %d", tc.provider, tc.status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()
			req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = (&ProviderConfig{httpClient: srv.Client()}).evalProbe(req, tc.provider)
			if code, status := answer(t, err); code != tc.wantCode || status != tc.wantStatus {
				t.Errorf("answer = %s %d, want %s %d", code, status, tc.wantCode, tc.wantStatus)
			}
		})
	}

	t.Run("unreachable", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		url, client := srv.URL, srv.Client()
		srv.Close()
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		err = (&ProviderConfig{httpClient: client}).evalProbe(req, "openai")
		if code, status := answer(t, err); code != errs.CodeQeetAIProviderUnreachable || status != http.StatusBadRequest {
			t.Errorf("answer = %s %d, want %s 400", code, status, errs.CodeQeetAIProviderUnreachable)
		}
	})
}

// TestStreamMessagesUnconfigured checks that posting a message with no provider
// configured answers 409 qeetai_unconfigured.
func TestStreamMessagesUnconfigured(t *testing.T) {
	h := &Handler{Service: &stubStore{}, Resolver: stubResolver{source: SourceNone}}
	rec := httptest.NewRecorder()
	h.streamMessages(rec, newHandlerRequest(uuid.New(), uuid.New(), uuid.New(), `{"message":"hello"}`))
	if code := bodyCode(t, rec); rec.Code != http.StatusConflict || code != errs.CodeQeetAIUnconfigured {
		t.Errorf("answer = %s %d, want %s 409", code, rec.Code, errs.CodeQeetAIUnconfigured)
	}
}

// answer returns the error code and HTTP status a handler writes for err.
func answer(t *testing.T, err error) (string, int) {
	t.Helper()
	if err == nil {
		t.Fatal("got no error")
	}
	rec := httptest.NewRecorder()
	httpx.WriteError(rec, httptest.NewRequest(http.MethodPost, "/", nil), err)
	return bodyCode(t, rec), rec.Code
}

// bodyCode returns the error code of a JSON error response.
func bodyCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %d response: %v\nbody: %s", rec.Code, err, rec.Body)
	}
	return body.Error.Code
}
