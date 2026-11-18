//go:build integration

package scim

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// tokenOrg is an organization with an administrator managing its SCIM tokens
// and the SCIM endpoint its identity provider calls.
type tokenOrg struct {
	id      uuid.UUID
	adminID uuid.UUID
	admin   http.Handler
	scim    chi.Router
	tokens  string // the admin path of its token list
}

func newTokenOrg(t *testing.T) *tokenOrg {
	t.Helper()
	id := dbtest.Organization(t)
	admin := dbtest.User(t, id, id)
	h := &Handler{Service: newTestService(t, dbtest.Pool(t))}
	r := chi.NewRouter()
	h.MountPublic(r)
	return &tokenOrg{
		id:      id,
		adminID: admin.ID,
		admin:   dbtest.Serve(dbtest.Principal(admin.ID, id), h.Mount),
		scim:    r,
		tokens:  "/organizations/" + id.String() + "/scim/tokens",
	}
}

// issued is the answer to creating or rotating a token.
type issued struct {
	Token     string `json:"token"`
	SCIMToken Token  `json:"scim_token"`
	Replaced  *Token `json:"replaced"`
}

func (o *tokenOrg) create(t *testing.T, body map[string]any) issued {
	t.Helper()
	rec := dbtest.Do(t, o.admin, http.MethodPost, o.tokens, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create a token: %d %s", rec.Code, rec.Body.String())
	}
	var out issued
	dbtest.Decode(t, rec, &out)
	return out
}

func (o *tokenOrg) list(t *testing.T) map[uuid.UUID]Token {
	t.Helper()
	rec := dbtest.Do(t, o.admin, http.MethodGet, o.tokens, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list the tokens: %d %s", rec.Code, rec.Body.String())
	}
	var page struct {
		Items []Token `json:"items"`
	}
	dbtest.Decode(t, rec, &page)
	out := map[uuid.UUID]Token{}
	for _, tok := range page.Items {
		out[tok.ID] = tok
	}
	return out
}

// provision calls the SCIM endpoint with token and returns the status.
func (o *tokenOrg) provision(t *testing.T, token, path string) int {
	t.Helper()
	req := httptest.NewRequestWithContext(dbtest.Context(t), http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	o.scim.ServeHTTP(rec, req)
	return rec.Code
}

func (o *tokenOrg) works(t *testing.T, token string) bool {
	t.Helper()
	switch code := o.provision(t, token, "/scim/v2/Users"); code {
	case http.StatusOK:
		return true
	case http.StatusUnauthorized:
		return false
	default:
		t.Fatalf("SCIM call: status %d", code)
		return false
	}
}

// TestSCIMTokenRotatesWithOverlap checks that a rotated token keeps working
// beside its replacement until the overlap ends, and that a revoked one stops.
func TestSCIMTokenRotatesWithOverlap(t *testing.T) {
	o := newTokenOrg(t)
	first := o.create(t, map[string]any{"name": "Okta"})
	if first.SCIMToken.Status != TokenActive || first.SCIMToken.Name != "Okta" || first.Token == "" {
		t.Fatalf("created %+v", first)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.scim_tokens WHERE id = $1 AND token_hash = $2`, first.SCIMToken.ID, codes.Hash(first.Token)); n != 1 {
		t.Fatal("the token is not stored as its hash")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.scim_tokens WHERE id = $1 AND organization_id = $2 AND created_by = $3`, first.SCIMToken.ID, o.id, o.adminID); n != 1 {
		t.Error("the token doesn't record who created it")
	}
	if !o.works(t, first.Token) {
		t.Fatal("a new token is refused")
	}

	rec := dbtest.Do(t, o.admin, http.MethodPost, o.tokens+"/"+first.SCIMToken.ID.String()+"/rotate", map[string]any{"overlap_hours": 24})
	if rec.Code != http.StatusCreated {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body.String())
	}
	var rotated issued
	dbtest.Decode(t, rec, &rotated)
	old := rotated.Replaced
	if old == nil || old.Status != TokenRotated || old.ReplacedBy == nil || *old.ReplacedBy != rotated.SCIMToken.ID {
		t.Fatalf("the rotated token reads %+v, want rotated and replaced by %s", old, rotated.SCIMToken.ID)
	}
	if old.ExpiresAt == nil || time.Until(*old.ExpiresAt) < 23*time.Hour || time.Until(*old.ExpiresAt) > 25*time.Hour {
		t.Errorf("the rotated token works until %v, want in a day", old.ExpiresAt)
	}
	if rotated.SCIMToken.Name != "Okta" || rotated.SCIMToken.Status != TokenActive {
		t.Errorf("the replacement reads %+v", rotated.SCIMToken)
	}
	if !o.works(t, first.Token) || !o.works(t, rotated.Token) {
		t.Fatal("during the overlap both tokens must work")
	}
	if got := o.list(t)[first.SCIMToken.ID].Status; got != TokenRotated {
		t.Errorf("listed as %q, want rotated", got)
	}
	if rec := dbtest.Do(t, o.admin, http.MethodPost, o.tokens+"/"+first.SCIMToken.ID.String()+"/rotate", nil); rec.Code != http.StatusConflict {
		t.Errorf("rotating a rotated token: %d, want 409", rec.Code)
	}

	// The overlap ends.
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `UPDATE organization.scim_tokens SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1`, first.SCIMToken.ID); err != nil {
		t.Fatal(err)
	}
	if o.works(t, first.Token) {
		t.Error("a rotated token works after its overlap")
	}
	if !o.works(t, rotated.Token) {
		t.Fatal("the replacement stopped with the old token")
	}
	if got := o.list(t)[first.SCIMToken.ID].Status; got != TokenExpired {
		t.Errorf("listed as %q after the overlap, want expired", got)
	}

	// Rotating without an overlap stops the old token at once.
	rec = dbtest.Do(t, o.admin, http.MethodPost, o.tokens+"/"+rotated.SCIMToken.ID.String()+"/rotate", map[string]any{"overlap_hours": 0})
	if rec.Code != http.StatusCreated {
		t.Fatalf("rotate with no overlap: %d %s", rec.Code, rec.Body.String())
	}
	var third issued
	dbtest.Decode(t, rec, &third)
	if o.works(t, rotated.Token) || !o.works(t, third.Token) {
		t.Error("a rotation with no overlap must stop the old token and start the new one")
	}

	if rec := dbtest.Do(t, o.admin, http.MethodDelete, o.tokens+"/"+third.SCIMToken.ID.String(), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body.String())
	}
	if o.works(t, third.Token) {
		t.Error("a revoked token works")
	}
	if got := o.list(t)[third.SCIMToken.ID]; got.Status != TokenRevoked || got.RevokedAt == nil {
		t.Errorf("listed as %+v, want revoked", got)
	}
	if rec := dbtest.Do(t, o.admin, http.MethodDelete, o.tokens+"/"+third.SCIMToken.ID.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("revoking a revoked token: %d, want 404", rec.Code)
	}

	var actions []string
	rows, err := dbtest.Pool(t).Query(dbtest.Context(t), `
		SELECT action FROM audit.events WHERE organization_id = $1 AND resource_type = 'scim_token' AND resource_id IS NOT NULL
	`, o.id)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatal(err)
		}
		actions = append(actions, a)
	}
	rows.Close()
	slices.Sort(actions)
	if want := []string{"scim.token_created", "scim.token_revoked", "scim.token_rotated", "scim.token_rotated"}; !slices.Equal(actions, want) {
		t.Errorf("recorded %v, want %v", actions, want)
	}
}

// TestSCIMTokenStopsWithItsExpiryAndOrganization checks that an expired token
// is refused, and every token of an organization that is suspended or due for
// deletion, for as long as it is.
func TestSCIMTokenStopsWithItsExpiryAndOrganization(t *testing.T) {
	o := newTokenOrg(t)
	if rec := dbtest.Do(t, o.admin, http.MethodPost, o.tokens, map[string]any{"name": "Entra", "expires_at": time.Now().Add(-time.Minute)}); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("a token expiring in the past: %d, want 422", rec.Code)
	}
	for _, name := range []string{"", "   ", strings.Repeat("a", maxTokenNameLen+1)} {
		if rec := dbtest.Do(t, o.admin, http.MethodPost, o.tokens, map[string]any{"name": name}); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("a token named %q: %d, want 422", name, rec.Code)
		}
	}
	expiring := o.create(t, map[string]any{"name": "Entra", "expires_at": time.Now().Add(time.Hour)})
	lasting := o.create(t, map[string]any{"name": "Okta"})
	if expiring.SCIMToken.ExpiresAt == nil || !o.works(t, expiring.Token) {
		t.Fatalf("a token expiring in an hour: %+v", expiring.SCIMToken)
	}
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `UPDATE organization.scim_tokens SET expires_at = NOW() WHERE id = $1`, expiring.SCIMToken.ID); err != nil {
		t.Fatal(err)
	}
	if o.works(t, expiring.Token) {
		t.Error("an expired token works")
	}
	if rec := dbtest.Do(t, o.admin, http.MethodPost, o.tokens+"/"+expiring.SCIMToken.ID.String()+"/rotate", nil); rec.Code != http.StatusConflict {
		t.Errorf("rotating an expired token: %d, want 409", rec.Code)
	}

	for _, tc := range []struct{ name, stop, resume string }{
		{"suspended", `UPDATE organization.organizations SET status = 'suspended' WHERE id = $1`, `UPDATE organization.organizations SET status = 'active' WHERE id = $1`},
		{"due for deletion", `UPDATE organization.organizations SET deletion_due_at = NOW() + INTERVAL '30 days' WHERE id = $1`, `UPDATE organization.organizations SET deletion_due_at = NULL WHERE id = $1`},
		{"deleted", `UPDATE organization.organizations SET deleted_at = NOW() WHERE id = $1`, `UPDATE organization.organizations SET deleted_at = NULL WHERE id = $1`},
	} {
		if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), tc.stop, o.id); err != nil {
			t.Fatal(err)
		}
		if o.works(t, lasting.Token) {
			t.Errorf("a token of an organization %s works", tc.name)
		}
		if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), tc.resume, o.id); err != nil {
			t.Fatal(err)
		}
		if !o.works(t, lasting.Token) {
			t.Errorf("a token of an organization no longer %s is refused", tc.name)
		}
	}
}

// TestSCIMTokenRecordsUseOncePerMinute checks that a token's last use is
// written on first use and again only once a minute has passed.
func TestSCIMTokenRecordsUseOncePerMinute(t *testing.T) {
	o := newTokenOrg(t)
	tok := o.create(t, map[string]any{"name": "Okta"})
	lastUsed := func() time.Time {
		t.Helper()
		var at *time.Time
		if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `SELECT last_used_at FROM organization.scim_tokens WHERE id = $1`, tok.SCIMToken.ID).Scan(&at); err != nil {
			t.Fatal(err)
		}
		if at == nil {
			t.Fatal("no use recorded")
		}
		return *at
	}
	o.works(t, tok.Token)
	first := lastUsed()
	o.works(t, tok.Token)
	if again := lastUsed(); !again.Equal(first) {
		t.Errorf("a second use within the minute was written: %v, then %v", first, again)
	}
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `UPDATE organization.scim_tokens SET last_used_at = NOW() - INTERVAL '2 minutes' WHERE id = $1`, tok.SCIMToken.ID); err != nil {
		t.Fatal(err)
	}
	o.works(t, tok.Token)
	if later := lastUsed(); time.Since(later) > time.Minute {
		t.Errorf("a use after a minute was not written: %v", later)
	}
}

// TestSCIMTokenLimit checks that an organization can't hold more working
// tokens than the cap, and that a rotation, which replaces one, is not held to it.
func TestSCIMTokenLimit(t *testing.T) {
	o := newTokenOrg(t)
	var last issued
	for i := range maxLiveTokens {
		last = o.create(t, map[string]any{"name": "IdP " + string(rune('A'+i))})
	}
	if rec := dbtest.Do(t, o.admin, http.MethodPost, o.tokens, map[string]any{"name": "one too many"}); rec.Code != http.StatusConflict {
		t.Errorf("a token over the cap: %d, want 409", rec.Code)
	}
	if rec := dbtest.Do(t, o.admin, http.MethodPost, o.tokens+"/"+last.SCIMToken.ID.String()+"/rotate", nil); rec.Code != http.StatusCreated {
		t.Errorf("rotating at the cap: %d %s", rec.Code, rec.Body.String())
	}
}

// TestSCIMTokensStayInTheirOrganization checks that an administrator can't
// list, rotate or revoke another organization's tokens, and that one
// organization's token reaches none of another's data.
func TestSCIMTokensStayInTheirOrganization(t *testing.T) {
	a, b := newTokenOrg(t), newTokenOrg(t)
	mine := a.create(t, map[string]any{"name": "A"})
	theirs := b.create(t, map[string]any{"name": "B"})
	victim := dbtest.User(t, b.id)

	if got := a.list(t); len(got) != 1 || got[mine.SCIMToken.ID].Name != "A" {
		t.Errorf("A lists %v, want only its own token", got)
	}
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, b.tokens},
		{http.MethodPost, b.tokens},
		{http.MethodPost, b.tokens + "/" + theirs.SCIMToken.ID.String() + "/rotate"},
		{http.MethodDelete, b.tokens + "/" + theirs.SCIMToken.ID.String()},
	} {
		if rec := dbtest.Do(t, a.admin, tc.method, tc.path, map[string]any{"name": "x"}); rec.Code != http.StatusForbidden {
			t.Errorf("A %s %s: %d, want 403", tc.method, tc.path, rec.Code)
		}
	}
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, a.tokens + "/" + theirs.SCIMToken.ID.String() + "/rotate"},
		{http.MethodDelete, a.tokens + "/" + theirs.SCIMToken.ID.String()},
	} {
		if rec := dbtest.Do(t, a.admin, tc.method, tc.path, nil); rec.Code != http.StatusNotFound {
			t.Errorf("A %s B's token under its own path: %d, want 404", tc.method, rec.Code)
		}
	}
	if got := b.list(t)[theirs.SCIMToken.ID]; got.Status != TokenActive || !b.works(t, theirs.Token) {
		t.Errorf("B's token after A's attempts: %+v", got)
	}
	if code := a.provision(t, mine.Token, "/scim/v2/Users/"+victim.ID.String()); code != http.StatusNotFound {
		t.Errorf("A's token reads B's user: %d, want 404", code)
	}
	if code := b.provision(t, theirs.Token, "/scim/v2/Users/"+victim.ID.String()); code != http.StatusOK {
		t.Errorf("B's token reads its own user: %d, want 200", code)
	}
}

// TestSCIMSingleTokenRoutesMapOntoTokens checks the single-token routes: a
// rotation replaces every token at once, and a revocation stops them all.
func TestSCIMSingleTokenRoutesMapOntoTokens(t *testing.T) {
	o := newTokenOrg(t)
	legacy := "/organizations/" + o.id.String() + "/scim/token"
	// A token from before several were possible, as the migration leaves it.
	before := tokenPrefix + uuid.NewString()
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `
		INSERT INTO organization.scim_tokens (organization_id, token_hash, token_prefix) VALUES ($1, $2, $3)
	`, o.id, codes.Hash(before), tokenPrefix+"before"); err != nil {
		t.Fatal(err)
	}
	if !o.works(t, before) {
		t.Fatal("a token from before is refused")
	}
	named := o.create(t, map[string]any{"name": "Okta"})

	rotate := func() string {
		t.Helper()
		rec := dbtest.Do(t, o.admin, http.MethodPost, legacy, nil)
		if rec.Code != http.StatusCreated {
			t.Fatalf("rotate the token: %d %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Token  string     `json:"token"`
			Config ConfigView `json:"config"`
		}
		dbtest.Decode(t, rec, &out)
		if !out.Config.TokenSet || out.Config.TokenCount != 1 {
			t.Errorf("config after rotating: %+v, want one token", out.Config)
		}
		return out.Token
	}
	current := rotate()
	if o.works(t, before) || o.works(t, named.Token) || !o.works(t, current) {
		t.Fatal("rotating the token must stop every other at once")
	}
	if got := o.list(t)[named.SCIMToken.ID]; got.Status != TokenRevoked || got.ReplacedBy == nil {
		t.Errorf("a token the rotation replaced reads %+v", got)
	}
	next := rotate()
	if o.works(t, current) || !o.works(t, next) {
		t.Error("a second rotation must replace the first")
	}

	if rec := dbtest.Do(t, o.admin, http.MethodDelete, legacy, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke the token: %d", rec.Code)
	}
	if o.works(t, next) {
		t.Error("a token works after the revocation")
	}
	if rec := dbtest.Do(t, o.admin, http.MethodDelete, legacy, nil); rec.Code != http.StatusNotFound {
		t.Errorf("revoking with none left: %d, want 404", rec.Code)
	}
	rec := dbtest.Do(t, o.admin, http.MethodGet, "/organizations/"+o.id.String()+"/scim", nil)
	var cfg ConfigView
	dbtest.Decode(t, rec, &cfg)
	if cfg.TokenSet || cfg.TokenCount != 0 {
		t.Errorf("config with every token revoked: %+v", cfg)
	}
}
