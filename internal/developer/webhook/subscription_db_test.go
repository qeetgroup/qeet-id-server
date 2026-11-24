//go:build integration

package webhook

import (
	"net/http"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/requestsig"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestRotatedSecretOverlaps checks that after a rotation deliveries are signed
// with the new secret and the old one until the overlap ends, then the new
// one alone.
func TestRotatedSecretOverlaps(t *testing.T) {
	svc, ep := dispatchService(t), newEndpoint(t)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization)
	dbtest.Assign(t, admin.ID, organization, dbtest.Role(t, organization, "webhook.write"))
	sub := subscribe(t, svc, organization, ep.URL, "group.created")

	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: svc}).Mount)
	rec := dbtest.Do(t, asAdmin, http.MethodPost, "/organizations/"+organization.String()+"/webhooks/"+sub.ID.String()+"/rotate-secret", nil)
	var rotated struct {
		Secret                  string    `json:"secret"`
		PreviousSecretExpiresAt time.Time `json:"previous_secret_expires_at"`
	}
	dbtest.Decode(t, rec, &rotated)
	if rec.Code != http.StatusOK || rotated.Secret == "" || rotated.Secret == sub.Secret ||
		time.Until(rotated.PreviousSecretExpiresAt) < SecretRotationOverlap-time.Minute {
		t.Fatalf("rotate: %d %s; want a new secret and the old one kept for the overlap", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'webhook.secret_rotated' AND resource_id = $1`, sub.ID); n != 1 {
		t.Error("the rotation was not audited")
	}

	dispatch(t, svc, groupCreated(organization))
	got, _ := ep.last("group.created")
	timestamp := got.header.Get("X-Qeet-Timestamp")
	want := "sha256=" + requestsig.Sign(rotated.Secret, timestamp, got.body) + ",sha256=" + requestsig.Sign(sub.Secret, timestamp, got.body)
	if got.header.Get("X-Qeet-Signature") != want {
		t.Errorf("during the overlap: signature %q; want the new secret's then the old one's", got.header.Get("X-Qeet-Signature"))
	}

	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `UPDATE organization.webhook_subscriptions SET previous_secret_expires_at = NOW() - interval '1 minute' WHERE id = $1`, sub.ID); err != nil {
		t.Fatal(err)
	}
	dispatch(t, svc, groupCreated(organization))
	got, _ = ep.last("group.created")
	if want := "sha256=" + requestsig.Sign(rotated.Secret, got.header.Get("X-Qeet-Timestamp"), got.body); got.header.Get("X-Qeet-Signature") != want {
		t.Errorf("after the overlap: signature %q; want the new secret's alone", got.header.Get("X-Qeet-Signature"))
	}
}
