//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/social"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// An account keeps at least one way to sign in. Removing its last passkey,
// its last connected account, or (by an administrator) its last linked
// identity is refused with a stated reason and recorded, wherever the removal
// comes from; the method keeps working. Count and removal happen together, so
// two removals at once cannot both succeed.

func refusalAudits(t *testing.T, ctx context.Context, userID uuid.UUID) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM audit.events WHERE action = 'auth.sign_in_method_removal_refused' AND resource_id = $1`, userID).Scan(&n); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	return n
}

func passkeyExists(t *testing.T, ctx context.Context, id uuid.UUID) bool {
	t.Helper()
	var ok bool
	if err := testPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM auth.passkey_credentials WHERE id = $1)`, id).Scan(&ok); err != nil {
		t.Fatalf("read passkey: %v", err)
	}
	return ok
}

// TestLastPasskeyIsKept covers: removing a passkey alongside a password
// succeeds; removing the only passkey is refused with a reason, recorded, and
// the passkey still signs in; another person's passkey cannot be removed;
// after enrolling a second passkey the removal succeeds; the counts are
// reported.
func TestLastPasskeyIsKept(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	authSvc, _ := newAuth()
	authSvc.SetRegistrationPolicy(allowSelfRegistration{})
	svc := newPasskeySvcWithAuth(t, authSvc)
	tenantID := createTenant(t, ctx, uniqueSlug("lastpk"))

	t.Run("a password remains", func(t *testing.T) {
		me := createUserInTenant(t, ctx, tenantID)
		if _, err := testPool.Exec(ctx, `INSERT INTO auth.password_credentials (user_id, password_hash) VALUES ($1, 'x')`, me); err != nil {
			t.Fatal(err)
		}
		pk := seedPasskey(t, ctx, me, nil)
		if rr := callPasskeyAPI(t, passkeyAPI(svc, me, tenantID), http.MethodDelete, "/passkeys/"+pk.String(), nil, ""); rr.Code != http.StatusNoContent {
			t.Fatalf("remove a passkey beside a password: %d %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("the only passkey", func(t *testing.T) {
		// A passkey-first account, signed up through the real ceremony so the
		// passkey can be shown to still sign in.
		rp := virtualwebauthn.RelyingParty{Name: pkRPName, ID: pkRPID, Origin: pkRPOrigin}
		a := virtualwebauthn.NewAuthenticator()
		c := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
		sid, creation, err := svc.BeginSignup(ctx, uniqueSlug("lastpk")+"@example.com", "")
		if err != nil {
			t.Fatal(err)
		}
		optsJSON, _ := json.Marshal(creation)
		opts, err := virtualwebauthn.ParseAttestationOptions(string(optsJSON))
		if err != nil {
			t.Fatal(err)
		}
		a.Options.UserHandle = []byte(opts.UserID)
		_, me, err := svc.FinishSignup(ctx, sid, json.RawMessage(virtualwebauthn.CreateAttestationResponse(rp, a, c, *opts)), "", "203.0.113.7", "test")
		if err != nil {
			t.Fatalf("passkey sign-up: %v", err)
		}
		a.AddCredential(c)
		var only uuid.UUID
		if err := testPool.QueryRow(ctx, `SELECT id FROM auth.passkey_credentials WHERE user_id = $1`, me).Scan(&only); err != nil {
			t.Fatal(err)
		}
		api := passkeyAPI(svc, me, uuid.Nil)

		rr := callPasskeyAPI(t, api, http.MethodDelete, "/passkeys/"+only.String(), nil, "")
		if rr.Code != http.StatusConflict || errorCode(t, rr) != errs.CodeAuthLastSignInMethod {
			t.Fatalf("remove the only passkey: %d %s", rr.Code, rr.Body.String())
		}
		if !passkeyExists(t, ctx, only) || refusalAudits(t, ctx, me) != 1 {
			t.Error("the refused removal deleted the passkey or was not recorded")
		}
		loginSID, assertion, err := svc.BeginLogin(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		assertJSON, _ := json.Marshal(assertion)
		aopts, _ := virtualwebauthn.ParseAssertionOptions(string(assertJSON))
		if pair, err := svc.FinishLogin(ctx, loginSID, json.RawMessage(virtualwebauthn.CreateAssertionResponse(rp, a, c, *aopts)), "203.0.113.7", "test"); err != nil || pair.UserID != me {
			t.Fatalf("the kept passkey no longer signs in: %v", err)
		}

		// Someone else's passkey is not theirs to remove.
		other := createUserInTenant(t, ctx, tenantID)
		otherPK := seedPasskey(t, ctx, other, nil)
		seedPasskey(t, ctx, other, nil)
		if rr := callPasskeyAPI(t, api, http.MethodDelete, "/passkeys/"+otherPK.String(), nil, ""); rr.Code != http.StatusNotFound || !passkeyExists(t, ctx, otherPK) {
			t.Errorf("removing another person's passkey: %d, kept %v", rr.Code, passkeyExists(t, ctx, otherPK))
		}

		seedPasskey(t, ctx, me, nil)
		if rr := callPasskeyAPI(t, api, http.MethodDelete, "/passkeys/"+only.String(), nil, ""); rr.Code != http.StatusNoContent {
			t.Fatalf("remove after enrolling a second passkey: %d %s", rr.Code, rr.Body.String())
		}
		counts, err := authSvc.SignInMethods(ctx, me)
		if err != nil || counts.Total() != 1 || counts.Passkeys != 1 || counts.Password {
			t.Errorf("sign-in methods = %+v (%v), want the one passkey left", counts, err)
		}
	})

	t.Run("two removals at once", func(t *testing.T) {
		me := createUserInTenant(t, ctx, tenantID)
		ids := []uuid.UUID{seedPasskey(t, ctx, me, nil), seedPasskey(t, ctx, me, nil)}
		var wg sync.WaitGroup
		results := make([]error, 2)
		for i, id := range ids {
			wg.Add(1)
			go func(i int, id uuid.UUID) {
				defer wg.Done()
				results[i] = svc.Delete(ctx, id, me, user.Remover{UserID: &me})
			}(i, id)
		}
		wg.Wait()
		ok := 0
		for _, err := range results {
			if err == nil {
				ok++
			}
		}
		left, _ := authSvc.SignInMethods(ctx, me)
		if ok != 1 || left.Total() != 1 {
			t.Fatalf("two simultaneous removals: %d succeeded (%v), %d ways left; want exactly one removed", ok, results, left.Total())
		}
	})
}

// TestLastLinkedIdentityIsKept covers: unlinking a person's only connected
// account, and an administrator unlinking someone's only linked identity, are
// refused and recorded; with another way in, both succeed.
func TestLastLinkedIdentityIsKept(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	authSvc, _ := newAuth()
	svc := social.NewService(testPool, authSvc, "http://app.local", egress.DevelopmentPolicy())
	svc.SetCipher(testEnvelope(t))
	tenantID := createTenant(t, ctx, uniqueSlug("lastsoc"))
	if _, err := svc.UpsertProvider(ctx, social.CreateProviderInput{
		TenantID: tenantID, Provider: "acme", ClientID: "cid", ClientSecret: "secret",
		DiscoveryURL: "https://idp.example/.well-known/openid-configuration",
	}); err != nil {
		t.Fatal(err)
	}
	mount := func(userID uuid.UUID) http.Handler {
		r := chi.NewRouter()
		r.Use(withPrincipal(userID, tenantID))
		(&social.Handler{Service: svc}).Mount(r)
		(&auth.Handler{Service: authSvc, Validate: validator.New()}).MountAuthed(r)
		return r
	}

	t.Run("own connected account", func(t *testing.T) {
		me := createUserInTenant(t, ctx, tenantID)
		var id uuid.UUID
		if err := testPool.QueryRow(ctx, `
			INSERT INTO auth.platform_social_identities (user_id, provider, subject, email)
			VALUES ($1, 'google', $2, 'me@example.com') RETURNING id`, me, uniqueSlug("sub")).Scan(&id); err != nil {
			t.Fatal(err)
		}
		api := mount(me)
		rr := callJSON(api, http.MethodGet, "/auth/sign-in-methods", nil)
		var counts struct {
			Total            int `json:"total"`
			LinkedIdentities int `json:"linked_identities"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &counts)
		if counts.Total != 1 || counts.LinkedIdentities != 1 {
			t.Errorf("sign-in methods: %s", rr.Body.String())
		}
		if rr := callJSON(api, http.MethodDelete, "/me/social/identities/"+id.String(), nil); errorCode(t, rr) != errs.CodeAuthLastSignInMethod {
			t.Fatalf("unlink the only connected account: %d %s", rr.Code, rr.Body.String())
		}
		if refusalAudits(t, ctx, me) != 1 {
			t.Error("the refusal was not recorded")
		}
		seedPasskey(t, ctx, me, nil)
		if rr := callJSON(api, http.MethodDelete, "/me/social/identities/"+id.String(), nil); rr.Code != http.StatusNoContent {
			t.Fatalf("unlink with a passkey left: %d %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("administrator unlinking", func(t *testing.T) {
		member := createUserInTenant(t, ctx, tenantID)
		var id uuid.UUID
		if err := testPool.QueryRow(ctx, `
			INSERT INTO "user".external_identities (user_id, tenant_id, provider, subject, email)
			VALUES ($1, $2, 'acme', $3, 'member@example.com') RETURNING id`, member, tenantID, uniqueSlug("sub")).Scan(&id); err != nil {
			t.Fatal(err)
		}
		admin := mount(createUserInTenant(t, ctx, tenantID))
		if rr := callJSON(admin, http.MethodDelete, "/social/identities/"+id.String(), nil); errorCode(t, rr) != errs.CodeAuthLastSignInMethod {
			t.Fatalf("administrator unlinking the only identity: %d %s", rr.Code, rr.Body.String())
		}
		if _, err := testPool.Exec(ctx, `INSERT INTO auth.password_credentials (user_id, password_hash) VALUES ($1, 'x')`, member); err != nil {
			t.Fatal(err)
		}
		if rr := callJSON(admin, http.MethodDelete, "/social/identities/"+id.String(), nil); rr.Code != http.StatusNoContent {
			t.Fatalf("administrator unlinking with a password left: %d %s", rr.Code, rr.Body.String())
		}
	})
}

// TestSwitchedOffMethodsDoNotCount: a passkey the organisation no longer lets
// anyone sign in with does not count as a way in, so it cannot keep the last
// working one from being protected.
func TestSwitchedOffMethodsDoNotCount(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	authSvc, _ := newAuth()
	svc := social.NewService(testPool, authSvc, "http://app.local", egress.DevelopmentPolicy())
	tenantID := createTenant(t, ctx, uniqueSlug("offmethods"))
	me := createUserInTenant(t, ctx, tenantID)
	seedPasskey(t, ctx, me, nil)
	var id uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO auth.platform_social_identities (user_id, provider, subject, email)
		VALUES ($1, 'google', $2, 'me@example.com') RETURNING id`, me, uniqueSlug("sub")).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if m, _ := authSvc.SignInMethods(ctx, me); m.Total() != 2 {
		t.Fatalf("with passkeys allowed: %+v, want 2 ways in", m)
	}
	setSignInMethods(t, ctx, tenantID, true, false, false, 15)
	if m, _ := authSvc.SignInMethods(ctx, me); m.Total() != 1 || m.Passkeys != 0 {
		t.Fatalf("with passkeys switched off: %+v, want only the connected account", m)
	}
	if err := svc.UnlinkForUser(ctx, id, me, user.Remover{UserID: &me}); err != errs.ErrAuthLastSignInMethod {
		t.Fatalf("unlinking the only working way in: %v, want refused", err)
	}
}
