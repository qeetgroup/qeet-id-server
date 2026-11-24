//go:build integration

package logincode

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

var (
	errRequired = errors.New("required")
	errInvalid  = errors.New("invalid")
	errUsed     = errors.New("used")
	errExpired  = errors.New("expired")
	errDraft    = errors.New("draft")
	errDisabled = errors.New("disabled")
	refusals    = Refusals{Required: errRequired, Invalid: errInvalid, Used: errUsed, Expired: errExpired, Draft: errDraft, Disabled: errDisabled}
)

// issuer is what issues codes of one kind, with the SQL that turns it off,
// puts it back to draft (none for a provider), turns it on and deletes it.
type issuer struct {
	code                           Code
	disable, draft, enable, remove string
}

// issuers returns one issuer of each kind in a fresh organization, signing in user.
func issuers(t *testing.T) []issuer {
	t.Helper()
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	user := dbtest.User(t, organization, organization).ID
	var saml, oidc uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO organization.saml_connections (organization_id, name, idp_entity_id, idp_sso_url, idp_certificate, status)
		VALUES ($1, 'Okta', 'https://idp.example.test', 'https://idp.example.test/sso', 'cert', 'active') RETURNING id`, organization).Scan(&saml); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO organization.oidc_connections (organization_id, name, issuer, client_id, client_secret_ct, client_secret_nonce, status)
		VALUES ($1, 'Entra', 'https://idp.example.test', 'qeet', 'ct', 'nonce', 'active') RETURNING id`, organization).Scan(&oidc); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO organization.social_providers (organization_id, provider, client_id, client_secret_ct, client_secret_nonce)
		VALUES ($1, 'okta', 'qeet', 'ct', 'nonce')`, organization); err != nil {
		t.Fatal(err)
	}
	return []issuer{
		{
			code:    Code{Kind: KindSAML, UserID: user, OrganizationID: organization, ConnectionID: saml},
			disable: `UPDATE organization.saml_connections SET status = 'disabled' WHERE organization_id = $1 AND id = $2`,
			draft:   `UPDATE organization.saml_connections SET status = 'draft' WHERE organization_id = $1 AND id = $2`,
			enable:  `UPDATE organization.saml_connections SET status = 'active' WHERE organization_id = $1 AND id = $2`,
			remove:  `DELETE FROM organization.saml_connections WHERE organization_id = $1 AND id = $2`,
		},
		{
			code:    Code{Kind: KindOIDCConnection, UserID: user, OrganizationID: organization, ConnectionID: oidc},
			disable: `UPDATE organization.oidc_connections SET status = 'disabled' WHERE organization_id = $1 AND id = $2`,
			draft:   `UPDATE organization.oidc_connections SET status = 'draft' WHERE organization_id = $1 AND id = $2`,
			enable:  `UPDATE organization.oidc_connections SET status = 'active' WHERE organization_id = $1 AND id = $2`,
			remove:  `DELETE FROM organization.oidc_connections WHERE organization_id = $1 AND id = $2`,
		},
		{
			code:    Code{Kind: KindSocial, UserID: user, OrganizationID: organization, Provider: "okta"},
			disable: `UPDATE organization.social_providers SET enabled = false WHERE organization_id = $1 AND provider = 'okta' AND $2::uuid IS NULL`,
			enable:  `UPDATE organization.social_providers SET enabled = true WHERE organization_id = $1 AND provider = 'okta' AND $2::uuid IS NULL`,
			remove:  `DELETE FROM organization.social_providers WHERE organization_id = $1 AND provider = 'okta' AND $2::uuid IS NULL`,
		},
		{code: Code{Kind: KindPlatformSocial, UserID: user}},
	}
}

// change runs sql on what issued c.
func change(t *testing.T, sql string, c Code) {
	t.Helper()
	var connection any
	if c.ConnectionID != uuid.Nil {
		connection = c.ConnectionID
	}
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), sql, c.OrganizationID, connection); err != nil {
		t.Fatal(err)
	}
}

// TestACodeSignsInOnce checks, for every kind, that a code trades once for
// whom it signs in, only as its own kind, and not once it has expired.
func TestACodeSignsInOnce(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	for _, is := range issuers(t) {
		t.Run(is.code.Kind, func(t *testing.T) {
			raw, err := Issue(ctx, pool, is.code, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			other := KindSocial
			if is.code.Kind == KindSocial {
				other = KindSAML
			}
			if _, err := Consume(ctx, pool, other, raw, refusals); !errors.Is(err, errInvalid) {
				t.Errorf("the code as a %s code: %v, want invalid", other, err)
			}
			got, err := Consume(ctx, pool, is.code.Kind, raw, refusals)
			if err != nil || got != is.code {
				t.Fatalf("the code: %+v, %v; want %+v", got, err, is.code)
			}
			if _, err := Consume(ctx, pool, is.code.Kind, raw, refusals); !errors.Is(err, errUsed) {
				t.Errorf("the code again: %v, want used", err)
			}
			if _, err := Consume(ctx, pool, is.code.Kind, "", refusals); !errors.Is(err, errRequired) {
				t.Errorf("no code: %v, want required", err)
			}
			if _, err := Consume(ctx, pool, is.code.Kind, "not-a-code", refusals); !errors.Is(err, errInvalid) {
				t.Errorf("an unknown code: %v, want invalid", err)
			}
			stale, err := Issue(ctx, pool, is.code, -time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Consume(ctx, pool, is.code.Kind, stale, refusals); !errors.Is(err, errExpired) {
				t.Errorf("an expired code: %v, want expired", err)
			}
		})
	}
}

// TestACodeOfAnIssuerTurnedOffSignsNobodyIn checks, for every kind with a
// connection or provider, that a code issued just before it was turned off,
// put back to draft or deleted is refused, and stays spent once it is back.
func TestACodeOfAnIssuerTurnedOffSignsNobodyIn(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	for _, is := range issuers(t) {
		if is.disable == "" {
			continue
		}
		t.Run(is.code.Kind, func(t *testing.T) {
			cases := []struct {
				sql  string
				want error
			}{{is.disable, errDisabled}, {is.draft, errDraft}}
			for _, tc := range cases {
				if tc.sql == "" {
					continue
				}
				raw, err := Issue(ctx, pool, is.code, time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				change(t, tc.sql, is.code)
				if _, err := Consume(ctx, pool, is.code.Kind, raw, refusals); !errors.Is(err, tc.want) {
					t.Errorf("%s, then its code: %v, want %v", tc.sql, err, tc.want)
				}
				change(t, is.enable, is.code)
				if _, err := Consume(ctx, pool, is.code.Kind, raw, refusals); !errors.Is(err, errUsed) {
					t.Errorf("the refused code once it is back on: %v, want used", err)
				}
			}
			raw, err := Issue(ctx, pool, is.code, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			change(t, is.remove, is.code)
			if _, err := Consume(ctx, pool, is.code.Kind, raw, refusals); !errors.Is(err, errInvalid) {
				t.Errorf("deleted, then its code: %v, want invalid", err)
			}
		})
	}
}

// TestARefusalTheFlowNamesNoErrorForStillRefuses checks that a flow which
// names no error for a refusal gets one anyway, never the code.
func TestARefusalTheFlowNamesNoErrorForStillRefuses(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	is := issuers(t)[0]
	raw, err := Issue(ctx, pool, is.code, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	change(t, is.draft, is.code)
	if got, err := Consume(ctx, pool, is.code.Kind, raw, Refusals{}); err == nil {
		t.Errorf("a draft connection's code with no draft error: %+v, want refused", got)
	}
}
