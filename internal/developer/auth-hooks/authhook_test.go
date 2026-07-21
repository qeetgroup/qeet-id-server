package authhook

import (
	"errors"
	"testing"
)

func TestDecide(t *testing.T) {
	callErr := errors.New("timeout")

	// Call failed, fail-open → allow.
	if _, denied, _ := decide(true, callErr, nil); denied {
		t.Error("fail-open must allow when the hook call errors")
	}
	// Call failed, fail-closed → deny.
	if _, denied, _ := decide(false, callErr, nil); !denied {
		t.Error("fail-closed must deny when the hook call errors")
	}
	// 2xx with explicit deny → deny (and carry the message).
	if msg, denied, _ := decide(true, nil, []byte(`{"decision":"deny","message":"blocked: off-hours"}`)); !denied || msg != "blocked: off-hours" {
		t.Errorf("explicit deny not honoured: msg=%q denied=%v", msg, denied)
	}
	// 2xx deny without a message → deny with a default message.
	if msg, denied, _ := decide(true, nil, []byte(`{"decision":"deny"}`)); !denied || msg == "" {
		t.Error("deny must always carry a non-empty message")
	}
	// 2xx allow → allow.
	if _, denied, _ := decide(true, nil, []byte(`{"decision":"allow"}`)); denied {
		t.Error("explicit allow must allow")
	}
	// 2xx with empty/garbage body → allow (default is permissive on success).
	if _, denied, _ := decide(true, nil, []byte(``)); denied {
		t.Error("empty success body must default to allow")
	}
	// 2xx allow with claims → claims are carried through untouched.
	if _, denied, claims := decide(true, nil, []byte(`{"decision":"allow","claims":{"plan":"enterprise"}}`)); denied || claims["plan"] != "enterprise" {
		t.Errorf("claims not carried through on allow: denied=%v claims=%v", denied, claims)
	}
	// deny must never carry claims, even if the hook body includes them.
	if _, denied, claims := decide(true, nil, []byte(`{"decision":"deny","claims":{"plan":"enterprise"}}`)); !denied || claims != nil {
		t.Errorf("deny must not carry claims: denied=%v claims=%v", denied, claims)
	}
}

func TestSignDeterministic(t *testing.T) {
	a := sign("secret", []byte("payload"))
	b := sign("secret", []byte("payload"))
	if a == "" || a != b {
		t.Error("sign must be deterministic and non-empty")
	}
	if sign("other", []byte("payload")) == a {
		t.Error("different secret must produce a different signature")
	}
}
