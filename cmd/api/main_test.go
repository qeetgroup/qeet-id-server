package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProbe(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	}))
	defer srv.Close()
	client := &http.Client{Timeout: time.Second}

	if err := probe(srv.URL+"/readyz", client); err != nil {
		t.Fatalf("200 must pass: %v", err)
	}
	for _, s := range []int{http.StatusServiceUnavailable, http.StatusNotFound, http.StatusMovedPermanently} {
		status = s
		if err := probe(srv.URL+"/readyz", client); err == nil {
			t.Errorf("status %d must fail", s)
		}
	}
	srv.Close()
	if err := probe(srv.URL+"/readyz", client); err == nil {
		t.Error("an unreachable server must fail")
	}
}

// TestSchemaCheckCantTell checks that schema-check exits 2 ("can't tell"), never
// 0, without a database to read, so the host stops rather than switching blind.
func TestSchemaCheckCantTell(t *testing.T) {
	if code := schemaCheck(""); code != 2 {
		t.Errorf("no DB_URL: exit %d, want 2", code)
	}
	if code := schemaCheck("postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1"); code != 2 {
		t.Errorf("unreachable database: exit %d, want 2", code)
	}
}
