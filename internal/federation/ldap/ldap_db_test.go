//go:build integration

package ldap

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// directory is a minimal LDAPv3 server for tests: simple binds checked against
// binds (DN to password), and searches answered from entries (uid to the
// entry's DN and attributes).
type directory struct {
	binds   map[string]string
	entries map[string]dirEntry
}

type dirEntry struct {
	dn    string
	attrs map[string]string
}

// start serves d on a loopback port until t ends and returns its ldap:// URL.
func (d *directory) start(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go d.serve(conn)
		}
	}()
	return "ldap://" + ln.Addr().String()
}

func (d *directory) serve(conn net.Conn) {
	defer conn.Close()
	for {
		p, err := ber.ReadPacket(conn)
		if err != nil || len(p.Children) < 2 {
			return
		}
		id, _ := p.Children[0].Value.(int64)
		op := p.Children[1]
		var replies []*ber.Packet
		switch op.Tag {
		case goldap.ApplicationBindRequest:
			dn, _ := op.Children[1].Value.(string)
			code := goldap.LDAPResultInvalidCredentials
			if want, ok := d.binds[dn]; ok && want == op.Children[2].Data.String() {
				code = goldap.LDAPResultSuccess
			}
			replies = append(replies, ldapResult(goldap.ApplicationBindResponse, code))
		case goldap.ApplicationSearchRequest:
			filter, _ := goldap.DecompileFilter(op.Children[6])
			uid := strings.TrimSuffix(strings.TrimPrefix(filter, "(uid="), ")")
			if e, ok := d.entries[uid]; ok {
				replies = append(replies, ldapEntry(e))
			}
			replies = append(replies, ldapResult(goldap.ApplicationSearchResultDone, goldap.LDAPResultSuccess))
		default:
			return
		}
		for _, reply := range replies {
			msg := ber.NewSequence("")
			msg.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
			msg.AppendChild(reply)
			if _, err := conn.Write(msg.Bytes()); err != nil {
				return
			}
		}
	}
}

func ldapResult(tag ber.Tag, code int) *ber.Packet {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(code), ""))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	return op
}

func ldapEntry(e dirEntry) *ber.Packet {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, goldap.ApplicationSearchResultEntry, nil, "")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.dn, ""))
	attrs := ber.NewSequence("")
	for name, value := range e.attrs {
		attr := ber.NewSequence("")
		attr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, ""))
		values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
		values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, ""))
		attr.AppendChild(values)
		attrs.AppendChild(attr)
	}
	op.AppendChild(attrs)
	return op
}

// noFactors is an MFA service whose accounts hold no second factor.
type noFactors struct{ auth.MFAEnroller }

func (noFactors) LoginFactors(context.Context, uuid.UUID) ([]auth.LoginFactor, error) {
	return nil, nil
}

// TestLoginAppliesSignInChecks checks that a directory sign-in is held to the
// sign-in lockout, counted across spellings of one username, and answers with
// a challenge for an account that must use a second factor, as well as signing
// in an account that has none.
func TestLoginAppliesSignInChecks(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	tenant := dbtest.Tenant(t)
	a := dbtest.User(t, tenant, tenant)
	const userDN = "uid=alice,dc=example,dc=test"
	dir := &directory{
		binds:   map[string]string{"cn=service,dc=example,dc=test": "service-secret", userDN: "alice-secret"},
		entries: map[string]dirEntry{"alice": {dn: userDN, attrs: map[string]string{"mail": a.Email, "cn": "Alice"}}},
	}
	var connID uuid.UUID
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenant.ldap_connections (tenant_id, name, server_url, bind_dn, bind_password, base_dn, status)
		VALUES ($1, 'Directory', $2, 'cn=service,dc=example,dc=test', 'service-secret', 'dc=example,dc=test', 'active')
		RETURNING id
	`, tenant, dir.start(t)).Scan(&connID); err != nil {
		t.Fatalf("connection: %v", err)
	}
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	authSvc.SetMFA(noFactors{})
	svc := NewService(pool, authSvc, egress.DevelopmentPolicy())

	res, err := svc.Login(ctx, connID, "alice", "alice-secret", "192.0.2.20", "test")
	if err != nil || res.Pair == nil || res.Pair.UserID != a.ID || res.Pair.TenantID == nil || *res.Pair.TenantID != tenant {
		t.Fatalf("sign in: %+v, %v", res, err)
	}

	if _, err := pool.Exec(ctx, `UPDATE "user".users SET mfa_required = TRUE WHERE id = $1`, a.ID); err != nil {
		t.Fatalf("require MFA: %v", err)
	}
	res, err = svc.Login(ctx, connID, "alice", "alice-secret", "192.0.2.20", "test")
	if err != nil || res.Pair != nil || !res.MFARequired || res.MFAToken == "" {
		t.Errorf("sign in to an account that must use a second factor: %+v, %v; want a challenge", res, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE "user".users SET mfa_required = FALSE WHERE id = $1`, a.ID); err != nil {
		t.Fatalf("lift MFA: %v", err)
	}

	for _, name := range []string{"alice", " alice", "ALICE", "alice  ", " Alice "} {
		if _, err := svc.Login(ctx, connID, name, "wrong", "192.0.2.20", "test"); !errors.Is(err, errs.ErrLDAPInvalidCredentials) {
			t.Fatalf("wrong password as %q: %v, want %v", name, err, errs.ErrLDAPInvalidCredentials)
		}
	}
	if _, err := svc.Login(ctx, connID, "alice", "alice-secret", "192.0.2.20", "test"); !errors.Is(err, errs.ErrAuthAccountLocked) {
		t.Errorf("right password after five wrong ones: %v, want %v", err, errs.ErrAuthAccountLocked)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE user_id = $1`, a.ID); n != 1 {
		t.Errorf("%d sessions, want only the first sign-in's", n)
	}
}
