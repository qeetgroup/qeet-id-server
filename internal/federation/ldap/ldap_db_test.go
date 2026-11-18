//go:build integration

package ldap

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
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
	multi map[string][]string // attributes with several values, such as memberOf
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
	all := map[string][]string{}
	for name, value := range e.attrs {
		all[name] = []string{value}
	}
	for name, values := range e.multi {
		all[name] = values
	}
	for name, vs := range all {
		attr := ber.NewSequence("")
		attr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, ""))
		values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
		for _, value := range vs {
			values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, ""))
		}
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

// operations records each directory operation as "operation status".
type operations struct {
	mu  sync.Mutex
	got []string
	ops []Operation
}

func (o *operations) RecordLDAPOperation(_ context.Context, op Operation) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.got = append(o.got, op.Operation+" "+http.StatusText(op.Status))
	o.ops = append(o.ops, op)
	return nil
}

// noLDAP is a plan without directory sign-in.
type noLDAP struct{}

func (noLDAP) FeatureAllowed(context.Context, uuid.UUID, string) (bool, error) { return false, nil }

// directoryService returns the LDAP service, allowed to reach loopback directories.
func directoryService(t *testing.T) *Service {
	t.Helper()
	pool := dbtest.Pool(t)
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	authSvc.SetMFA(noFactors{})
	return serviceOver(t, authSvc)
}

// serviceOver returns the LDAP service signing people in through authSvc,
// allowed to reach loopback directories and able to open what the tests seal.
func serviceOver(t *testing.T, authSvc *auth.Service) *Service {
	t.Helper()
	svc := NewService(dbtest.Pool(t), authSvc, egress.DevelopmentPolicy())
	svc.SetCipher(testCipher(t))
	return svc
}

// storedConnection stores an active directory connection of organization at
// serverURL, whose service account bindDN binds with "service-secret".
func storedConnection(t *testing.T, organization uuid.UUID, serverURL, bindDN string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	ct, nonce, err := testCipher(t).Seal(organization, "ldap-bind", id.String(), []byte("service-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `
		INSERT INTO organization.ldap_connections
		    (id, organization_id, name, server_url, bind_dn, bind_password_ct, bind_password_nonce, base_dn, status)
		VALUES ($1, $2, 'Directory', $3, $4, $5, $6, 'dc=example,dc=test', 'active')
	`, id, organization, serverURL, bindDN, ct, nonce); err != nil {
		t.Fatalf("connection: %v", err)
	}
	return id
}
