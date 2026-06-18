package siem

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sampleEvents() []AuditEvent {
	return []AuditEvent{
		{ID: "e1", TenantID: "t1", Action: "auth.login", ActorType: "user", CreatedAt: time.Unix(1700000000, 0)},
		{ID: "e2", TenantID: "t1", Action: "user.created", ActorType: "user", CreatedAt: time.Unix(1700000050, 0)},
	}
}

func TestBuildRequest_SplunkHEC(t *testing.T) {
	body, headers, err := buildRequest(typeSplunkHEC, "hec-tok", sampleEvents())
	if err != nil {
		t.Fatal(err)
	}
	if headers["Authorization"] != "Splunk hec-tok" {
		t.Errorf("missing/incorrect HEC auth header: %q", headers["Authorization"])
	}
	// HEC body is back-to-back JSON envelopes (one per line here).
	lines := strings.Count(strings.TrimSpace(string(body)), "\n") + 1
	if lines != 2 {
		t.Errorf("expected 2 HEC envelopes, got %d", lines)
	}
	if !strings.Contains(string(body), `"sourcetype":"qeet:audit"`) {
		t.Error("HEC envelope missing sourcetype")
	}
}

func TestBuildRequest_Datadog(t *testing.T) {
	body, headers, err := buildRequest(typeDatadog, "dd-key", sampleEvents())
	if err != nil {
		t.Fatal(err)
	}
	if headers["DD-API-KEY"] != "dd-key" {
		t.Errorf("missing DD-API-KEY header: %q", headers["DD-API-KEY"])
	}
	var arr []map[string]any
	if err := json.Unmarshal(body, &arr); err != nil {
		t.Fatalf("datadog body must be a JSON array: %v", err)
	}
	if len(arr) != 2 || arr[0]["ddsource"] != "qeet-id" {
		t.Errorf("unexpected datadog payload: %v", arr)
	}
}

func TestBuildRequest_HTTP(t *testing.T) {
	body, headers, err := buildRequest(typeHTTP, "bearer-tok", sampleEvents())
	if err != nil {
		t.Fatal(err)
	}
	if headers["Authorization"] != "Bearer bearer-tok" {
		t.Errorf("missing bearer header: %q", headers["Authorization"])
	}
	var env struct {
		Events []AuditEvent `json:"events"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("http body must be {events:[...]}: %v", err)
	}
	if len(env.Events) != 2 {
		t.Errorf("expected 2 events, got %d", len(env.Events))
	}
}

func TestBuildRequest_NoTokenOmitsAuth(t *testing.T) {
	_, headers, err := buildRequest(typeHTTP, "", sampleEvents())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := headers["Authorization"]; ok {
		t.Error("no token should mean no Authorization header")
	}
}
