package mfa

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

// TestSignInPayloadsStayAsTheAppsExpect pins the sign-in request the native apps read, and
// checks a notice carries its own words: active, not time-sensitive, and its text in the
// Android data so the app can show it.
func TestSignInPayloadsStayAsTheAppsExpect(t *testing.T) {
	id := uuid.MustParse("6f1c2b8a-3d4e-4f5a-8b9c-0d1e2f3a4b5c")
	raw, err := apnsPayload(signInMessage(id, "sign_in"))
	if err != nil {
		t.Fatal(err)
	}
	var apns map[string]any
	_ = json.Unmarshal(raw, &apns)
	aps := apns["aps"].(map[string]any)
	if apns["type"] != pushPayloadType || apns["challenge_id"] != id.String() || apns["action"] != "sign_in" ||
		aps["interruption-level"] != "time-sensitive" || aps["thread-id"] != "sign-in" {
		t.Errorf("sign-in APNs payload %s", raw)
	}
	raw, _ = fcmPayload("token", signInMessage(id, "sign_in"))
	var fcm struct {
		Message struct {
			Data    map[string]string `json:"data"`
			Android map[string]any    `json:"android"`
		} `json:"message"`
	}
	_ = json.Unmarshal(raw, &fcm)
	if len(fcm.Message.Data) != 3 || fcm.Message.Data["type"] != pushPayloadType || fcm.Message.Data["challenge_id"] != id.String() ||
		fcm.Message.Android["ttl"] != "120s" || fcm.Message.Android["collapse_key"] != id.String() {
		t.Errorf("sign-in FCM payload %s", raw)
	}

	notice := pushMessage{kind: "access_request", collapseID: "r1", title: "Access request", body: "Arjun Rao asks for Finance",
		data: map[string]string{"kind": "access_request", "access_request_id": "r1"}, ttl: noticeTTL, thread: "access_request", textInData: true}
	raw, _ = apnsPayload(notice)
	apns = nil
	_ = json.Unmarshal(raw, &apns)
	aps = apns["aps"].(map[string]any)
	alert := aps["alert"].(map[string]any)
	if apns["type"] != "access_request" || apns["access_request_id"] != "r1" || aps["interruption-level"] != "active" || alert["body"] != "Arjun Rao asks for Finance" {
		t.Errorf("notice APNs payload %s", raw)
	}
	raw, _ = fcmPayload("token", notice)
	_ = json.Unmarshal(raw, &fcm)
	if fcm.Message.Data["title"] != "Access request" || fcm.Message.Data["body"] != "Arjun Rao asks for Finance" || fcm.Message.Android["ttl"] != "86400s" {
		t.Errorf("notice FCM payload %s", raw)
	}
}
