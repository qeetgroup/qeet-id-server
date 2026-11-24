//go:build integration

package ldap

import (
	"context"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authentication/authtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// directory is a minimal LDAPv3 server for tests: simple binds checked against
// binds (DN to password), and searches answered from entries (uid to the
// entry's DN and attributes); a sync's search lists every entry. It refuses StartTLS.
type directory struct {
	binds   map[string]string
	entries map[string]dirEntry

	mu         sync.Mutex
	ln         net.Listener
	bound      []string // the DNs bound as, in order
	searches   []string // the filters searched, in order
	failSearch bool     // answer every search with an error
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
	d.mu.Lock()
	d.ln = ln
	d.mu.Unlock()
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

func (d *directory) stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	_ = d.ln.Close()
}

func (d *directory) bindsAs(dn string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, b := range d.bound {
		if b == dn {
			n++
		}
	}
	return n
}

func (d *directory) url() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return "ldap://" + d.ln.Addr().String()
}

func (d *directory) lastSearch() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.searches) == 0 {
		return ""
	}
	return d.searches[len(d.searches)-1]
}

func (d *directory) set(entries map[string]dirEntry) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.entries = entries
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
			d.mu.Lock()
			d.bound = append(d.bound, dn)
			want, ok := d.binds[dn]
			d.mu.Unlock()
			code := goldap.LDAPResultInvalidCredentials
			if ok && want == op.Children[2].Data.String() {
				code = goldap.LDAPResultSuccess
			}
			replies = append(replies, ldapResult(goldap.ApplicationBindResponse, code))
		case goldap.ApplicationSearchRequest:
			filter, _ := goldap.DecompileFilter(op.Children[6])
			replies = append(replies, d.search(filter)...)
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

var (
	uidFilter = regexp.MustCompile(`^\(uid=([^*()]+)\)$`)
	atLeast   = regexp.MustCompile(`\(([A-Za-z]+)>=([^)]+)\)`)
)

func (d *directory) search(filter string) []*ber.Packet {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.searches = append(d.searches, filter)
	if d.failSearch {
		return []*ber.Packet{ldapResult(goldap.ApplicationSearchResultDone, goldap.LDAPResultBusy)}
	}
	var replies []*ber.Packet
	if m := uidFilter.FindStringSubmatch(filter); m != nil {
		if e, ok := d.entries[m[1]]; ok {
			replies = append(replies, ldapEntry(e))
		}
		return append(replies, ldapResult(goldap.ApplicationSearchResultDone, goldap.LDAPResultSuccess))
	}
	uids := make([]string, 0, len(d.entries))
	for uid := range d.entries {
		uids = append(uids, uid)
	}
	sort.Strings(uids)
entries:
	for _, uid := range uids {
		e := d.entries[uid]
		for _, term := range atLeast.FindAllStringSubmatch(filter, -1) {
			if !newerOrEqual(e.attrs[term[1]], term[2]) {
				continue entries
			}
		}
		replies = append(replies, ldapEntry(e))
	}
	return append(replies, ldapResult(goldap.ApplicationSearchResultDone, goldap.LDAPResultSuccess))
}

// newerOrEqual compares uSNChanged as a number, modifyTimestamp as text.
func newerOrEqual(value, floor string) bool {
	v, verr := strconv.ParseInt(value, 10, 64)
	f, ferr := strconv.ParseInt(floor, 10, 64)
	if verr == nil && ferr == nil {
		return v >= f
	}
	return value != "" && value >= floor
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

// newAuthService is the sign-in service the directory signs people in
// through, its accounts holding no second factor.
func newAuthService(t *testing.T) *authentication.Service {
	t.Helper()
	return authtest.New(t, dbtest.Pool(t))
}

// directoryService returns the LDAP service, allowed to reach loopback
// directories, its dependencies changed by each of with.
func directoryService(t *testing.T, with ...func(*Deps)) *Service {
	t.Helper()
	return serviceOver(t, newAuthService(t), with...)
}

// serviceOver returns the LDAP service signing people in through authSvc,
// allowed to reach loopback directories and able to open what the tests seal.
func serviceOver(t *testing.T, authSvc *authentication.Service, with ...func(*Deps)) *Service {
	t.Helper()
	d := testDeps(dbtest.Pool(t), authSvc, testCipher(t))
	for _, change := range with {
		change(&d)
	}
	svc, err := NewService(d)
	if err != nil {
		t.Fatal(err)
	}
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
