//go:build integration

package siem

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// collector is a fake log endpoint: it keeps each request's path, credential
// header and body, and answers status.
type collector struct {
	*httptest.Server
	mu       sync.Mutex
	status   int
	requests []string
}

// newCollector starts a collector answering 200 until t ends.
func newCollector(t *testing.T) *collector {
	c := &collector{status: http.StatusOK}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.requests = append(c.requests, r.URL.Path+" "+r.Header.Get("Authorization")+r.Header.Get("DD-API-KEY")+" "+string(body))
		status := c.status
		c.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(c.Close)
	return c
}

// received returns the requests made to path.
func (c *collector) received(path string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, r := range c.requests {
		if strings.HasPrefix(r, path+" ") {
			out = append(out, r)
		}
	}
	return out
}
