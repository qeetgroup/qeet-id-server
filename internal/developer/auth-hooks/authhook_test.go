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

// TestDecideUnparseableBodyHonoursFailClosed checks that a 2xx answer with an
// unparseable body counts as no answer: denied for a fail-closed hook, allowed
// for a fail-open one.
func TestDecideUnparseableBodyHonoursFailClosed(t *testing.T) {
	bodies := map[string][]byte{
		"empty":           {},
		"truncated json":  []byte(`{"decision":`),
		"not json at all": []byte(`<html>502 Bad Gateway</html>`),
		"json array":      []byte(`["deny"]`),
		"bare string":     []byte(`"deny"`),
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			// fail_open=false: an undecidable answer must block.
			msg, denied, claims := decide(false, nil, body)
			if !denied {
				t.Errorf("fail-closed tenant: denied = false, want true (unparseable body must not allow)")
			}
			if msg == "" {
				t.Error("a denial must carry a user-facing message")
			}
			if claims != nil {
				t.Errorf("claims = %v, want nil on denial", claims)
			}

			// fail_open=true: unchanged, still allows.
			if _, denied, _ := decide(true, nil, body); denied {
				t.Error("fail-open tenant: denied = true, want false (documented default)")
			}
		})
	}

	// A well-formed body with no decision field is a valid "no objection" and
	// must still allow — that contract is unchanged.
	if _, denied, _ := decide(false, nil, []byte(`{}`)); denied {
		t.Error("well-formed empty object must allow; only unparseable bodies are undecidable")
	}
}
