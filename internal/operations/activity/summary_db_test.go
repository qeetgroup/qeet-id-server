//go:build integration

package activity

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestTheSummaryCountsWhatTheFiltersMatch checks that the summary totals the
// events of a category and a severity together, counts the API keys, agents
// and service principals acting beside the people, and covers windows past 90
// days with coarser buckets.
func TestTheSummaryCountsWhatTheFiltersMatch(t *testing.T) {
	ctx := dbtest.Context(t)
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	key1, key2, agent := uuid.NewString(), uuid.NewString(), uuid.NewString()
	insert := func(action, actorType string, actorUser *uuid.UUID, actorID string, ago time.Duration) {
		t.Helper()
		meta := map[string]any{}
		if actorID != "" {
			meta["actor_id"] = actorID
		}
		if _, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO audit.events (tenant_id, actor_type, actor_user_id, action, resource_type, metadata, created_at)
			VALUES ($1, $2, $3, $4, 'user', $5, NOW() - $6::interval)`, tenant, actorType, actorUser, action, meta, ago.String()); err != nil {
			t.Fatal(err)
		}
	}
	insert("auth.sign_in_failed", "user", &admin.ID, "", time.Hour)
	insert("auth.sign_in_failed", "user", &admin.ID, "", 2*time.Hour)
	insert("risk.check_failed", "api_key", &admin.ID, key1, time.Hour)
	insert("risk.rule_created", "api_key", nil, key2, time.Hour)
	insert("risk.rule_created", "agent", nil, agent, time.Hour)
	insert("user.created", "user", &admin.ID, "", 200*24*time.Hour)

	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), NewHandler(dbtest.Pool(t), NewHub(nil)).Mount)
	var got struct {
		Total         int64       `json:"total"`
		UniqueActors  int64       `json:"unique_actors"`
		Actors        actorCounts `json:"actors"`
		BucketSeconds int64       `json:"bucket_seconds"`
	}
	summary := func(v url.Values) {
		t.Helper()
		rec := dbtest.Do(t, h, http.MethodGet, "/activity/summary?"+v.Encode(), nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("summary %v: %d %s", v, rec.Code, rec.Body.String())
		}
		dbtest.Decode(t, rec, &got)
	}
	summary(url.Values{"category": {"security"}, "severity": {"error"}})
	if got.Total != 1 {
		t.Errorf("security errors: %d, want the API key's failed check", got.Total)
	}
	summary(url.Values{})
	if got.Total != 5 || got.UniqueActors != 1 || got.Actors.APIKeys != 2 || got.Actors.Agents != 1 || got.Actors.Services != 0 {
		t.Errorf("the day's summary: %+v, want 5 events by one person, two keys and an agent", got)
	}
	summary(url.Values{"from": {time.Now().Add(-300 * 24 * time.Hour).UTC().Format(time.RFC3339)}})
	if got.Total != 6 || got.BucketSeconds > 7*86400 || got.BucketSeconds < 86400 {
		t.Errorf("300 days: %d events in %ds buckets, want all 6 in buckets of a day to a week", got.Total, got.BucketSeconds)
	}
}
