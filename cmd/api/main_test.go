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
