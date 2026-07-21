package auth

import (
	"testing"

	"github.com/google/uuid"
)

func TestBuildReuseEvents_AuditShape(t *testing.T) {
	uid := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	tid := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	sid := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	rid := uuid.MustParse("44444444-4444-4444-8444-444444444444")
	in := RefreshInput{
		RefreshToken: "raw",
		IP:           "1.2.3.4",
		UserAgent:    "curl/8",
		RequestID:    "req-1",
	}

	ae, _ := buildReuseEvents(uid, tid, sid, rid, in)

	if ae.ActorType != "system" {
		t.Errorf("actor_type = %q, want system", ae.ActorType)
	}
	if ae.Action != "auth.token_reuse_detected" {
		t.Errorf("action = %q, want auth.token_reuse_detected", ae.Action)
	}
	if ae.ResourceType != "session" {
		t.Errorf("resource_type = %q, want session", ae.ResourceType)
	}
	if ae.ResourceID == nil || *ae.ResourceID != sid {
		t.Errorf("resource_id = %v, want %s", ae.ResourceID, sid)
	}
	if ae.TenantID == nil || *ae.TenantID != tid {
		t.Errorf("tenant_id = %v, want %s", ae.TenantID, tid)
	}
	if ae.ActorUserID == nil || *ae.ActorUserID != uid {
		t.Errorf("actor_user_id = %v, want %s", ae.ActorUserID, uid)
	}
	if ae.IP != "1.2.3.4" || ae.UserAgent != "curl/8" || ae.RequestID != "req-1" {
		t.Errorf("client context not propagated: %+v", ae)
	}
	if ae.Metadata["session_id"] != sid {
		t.Errorf("metadata.session_id = %v, want %s", ae.Metadata["session_id"], sid)
	}
	if ae.Metadata["refresh_token_id"] != rid {
		t.Errorf("metadata.refresh_token_id = %v, want %s", ae.Metadata["refresh_token_id"], rid)
	}
	if ae.Metadata["reason"] != "refresh_token_reuse" {
		t.Errorf("metadata.reason = %v, want refresh_token_reuse", ae.Metadata["reason"])
	}
	if ae.Metadata["ip"] != "1.2.3.4" || ae.Metadata["user_agent"] != "curl/8" {
		t.Errorf("metadata client context missing: %v", ae.Metadata)
	}
}

func TestBuildReuseEvents_OutboxShape(t *testing.T) {
	uid := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	tid := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	sid := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	rid := uuid.MustParse("44444444-4444-4444-8444-444444444444")
	in := RefreshInput{IP: "1.2.3.4", UserAgent: "ua"}

	_, oe := buildReuseEvents(uid, tid, sid, rid, in)

	if oe.Topic != "auth" {
		t.Errorf("topic = %q, want auth", oe.Topic)
	}
	if oe.EventType != "auth.session.revoked_for_reuse" {
		t.Errorf("event_type = %q, want auth.session.revoked_for_reuse", oe.EventType)
	}
	if oe.AggregateID != sid {
		t.Errorf("aggregate_id = %v, want session id %v", oe.AggregateID, sid)
	}
	payload, ok := oe.Payload.(map[string]any)
	if !ok {
		t.Fatalf("payload must be map[string]any, got %T", oe.Payload)
	}
	for _, k := range []string{"user_id", "tenant_id", "session_id", "ip", "user_agent"} {
		if _, present := payload[k]; !present {
			t.Errorf("payload missing key %q: %v", k, payload)
		}
	}
	if payload["user_id"] != uid {
		t.Errorf("payload.user_id = %v, want %s", payload["user_id"], uid)
	}
}

func TestBuildReuseEvents_OmitsEmptyClientContext(t *testing.T) {
	// When IP/UA are empty (e.g. older client) the metadata map should
	// NOT contain those keys at all rather than embed empty strings.
	uid := uuid.New()
	tid := uuid.New()
	sid := uuid.New()
	rid := uuid.New()
	ae, _ := buildReuseEvents(uid, tid, sid, rid, RefreshInput{})

	if _, ok := ae.Metadata["ip"]; ok {
		t.Errorf("metadata.ip should be omitted when empty: %v", ae.Metadata)
	}
	if _, ok := ae.Metadata["user_agent"]; ok {
		t.Errorf("metadata.user_agent should be omitted when empty: %v", ae.Metadata)
	}
	if _, ok := ae.Metadata["session_id"]; !ok {
		t.Errorf("metadata.session_id must always be present: %v", ae.Metadata)
	}
}
