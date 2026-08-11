package entitlements

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestNormalizePlan(t *testing.T) {
	cases := map[string]string{
		"free":         "free",
		"starter":      "starter",
		"pro":          "pro",
		"enterprise":   "enterprise",
		"starter_year": "starter", // annual variant folds to base tier
		"pro_year":     "pro",
		"PRO":          "pro", // case-insensitive
		"  free  ":     "free",
		"":             "free", // empty → free (fail-closed)
		"none":         "free", // GetSubscription "none" status → free
		"bogus":        "free", // unknown → free
	}
	for in, want := range cases {
		if got := NormalizePlan(in); got != want {
			t.Errorf("NormalizePlan(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCatalogCompleteAndFreeLimits(t *testing.T) {
	free := For("free")
	if free.Plan != "free" {
		t.Fatalf("plan = %q", free.Plan)
	}
	// Free includes the passwordless/core-login primitives...
	for _, f := range coreLogin {
		if !free.Features[f] {
			t.Errorf("free should include core feature %q", f)
		}
	}
	// ...and gates the premium ones.
	for _, f := range []string{FeatureSSO, FeatureSCIM, FeatureLDAP, FeatureWebhooks, FeatureAuditExport, FeatureAIQeetai, FeatureABAC} {
		if free.Features[f] {
			t.Errorf("free should NOT include premium feature %q", f)
		}
	}
	// Hard numeric limits.
	wantLimits := map[string]int{
		LimitSeats: 5, LimitApps: 3, LimitAPIKeys: 2, LimitCustomRoles: 0, LimitWebhooks: 0,
	}
	for k, want := range wantLimits {
		if free.Limits[k] != want {
			t.Errorf("free limit %q = %d, want %d", k, free.Limits[k], want)
		}
	}
}

func TestPaidTiersAreNoOp(t *testing.T) {
	// The enforced free limits must be Unlimited on every paid tier, so gates are
	// a no-op for paying customers.
	for _, plan := range []string{"starter", "pro", "enterprise"} {
		ent := For(plan)
		for _, k := range []string{LimitSeats, LimitApps, LimitAPIKeys, LimitCustomRoles, LimitWebhooks} {
			if ent.Limits[k] != Unlimited {
				t.Errorf("%s limit %q = %d, want Unlimited", plan, k, ent.Limits[k])
			}
		}
	}
	// SSO/SCIM/LDAP tier progression.
	if !For("pro").Features[FeatureSSO] {
		t.Error("pro should include SSO")
	}
	if For("pro").Features[FeatureSCIM] {
		t.Error("pro should NOT include SCIM (enterprise-only)")
	}
	if !For("enterprise").Features[FeatureSCIM] || !For("enterprise").Features[FeatureLDAP] {
		t.Error("enterprise should include SCIM + LDAP")
	}
}

func TestForReturnsCopy(t *testing.T) {
	a := For("free")
	a.Features[FeatureSSO] = true
	a.Limits[LimitSeats] = 999
	b := For("free")
	if b.Features[FeatureSSO] {
		t.Error("mutating a resolved copy leaked into the shared catalog (features)")
	}
	if b.Limits[LimitSeats] != 5 {
		t.Error("mutating a resolved copy leaked into the shared catalog (limits)")
	}
}

func TestLimitReached(t *testing.T) {
	cases := []struct {
		limit, current int
		want           bool
	}{
		{5, 4, false},
		{5, 5, true},
		{5, 6, true},
		{0, 0, true},            // free custom_roles/webhooks: none allowed
		{Unlimited, 999, false}, // unlimited never reached
	}
	for _, c := range cases {
		if got := LimitReached(c.limit, c.current); got != c.want {
			t.Errorf("LimitReached(%d,%d) = %v, want %v", c.limit, c.current, got, c.want)
		}
	}
}

type stubResolver struct {
	plan string
	err  error
}

func (s stubResolver) EffectivePlan(context.Context, uuid.UUID) (string, error) {
	return s.plan, s.err
}

func TestServiceResolveAndQueries(t *testing.T) {
	ctx := context.Background()
	tid := uuid.New()

	// Paid subscription → pro entitlements.
	svc := NewService(stubResolver{plan: "pro_year"})
	if allowed, _ := svc.FeatureAllowed(ctx, tid, FeatureSSO); !allowed {
		t.Error("pro should allow SSO")
	}
	if lim, _ := svc.Limit(ctx, tid, LimitSeats); lim != Unlimited {
		t.Errorf("pro seats = %d, want Unlimited", lim)
	}

	// Free (empty plan) → gated + capped.
	free := NewService(stubResolver{plan: ""})
	if allowed, _ := free.FeatureAllowed(ctx, tid, FeatureSSO); allowed {
		t.Error("free should NOT allow SSO")
	}
	if lim, _ := free.Limit(ctx, tid, LimitSeats); lim != 5 {
		t.Errorf("free seats = %d, want 5", lim)
	}

	// Nil resolver → free.
	nilSvc := NewService(nil)
	ent, err := nilSvc.Resolve(ctx, tid)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if ent.Plan != "free" {
		t.Errorf("nil resolver plan = %q, want free", ent.Plan)
	}

	// Unmodelled resource → Unlimited (fail-open).
	if lim, _ := free.Limit(ctx, tid, "nonexistent_resource"); lim != Unlimited {
		t.Errorf("unknown resource limit = %d, want Unlimited", lim)
	}
}
