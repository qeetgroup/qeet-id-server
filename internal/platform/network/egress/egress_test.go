package egress

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"testing"
)

type staticResolver map[string][]net.IP

func (r staticResolver) LookupIP(_ context.Context, _ string, host string) ([]net.IP, error) {
	return r[host], nil
}

func TestPublicPolicyURLValidation(t *testing.T) {
	policy := NewPolicy(Options{})
	for _, raw := range []string{
		"https://example.com/hook",
		"https://203.0.113.10/callback",
	} {
		if _, err := policy.ValidateHTTPURL(raw); err != nil {
			t.Errorf("public URL %q rejected: %v", raw, err)
		}
	}
	for _, raw := range []string{
		"http://example.com/hook",
		"https://localhost/hook",
		"https://127.0.0.1/hook",
		"https://[::1]/hook",
		"https://10.0.0.1/hook",
		"https://169.254.169.254/latest/meta-data",
		"https://user@example.com/hook",
		"https://example.com/hook#fragment",
	} {
		if _, err := policy.ValidateHTTPURL(raw); err == nil {
			t.Errorf("unsafe URL %q accepted", raw)
		}
	}
}

func TestDialRejectsMixedDNSAnswers(t *testing.T) {
	policy := NewPolicy(Options{Resolver: staticResolver{
		"mixed.example": {net.ParseIP("203.0.113.10"), net.ParseIP("127.0.0.1")},
	}})
	if _, err := policy.resolveAllowed(context.Background(), "mixed.example"); err == nil {
		t.Fatal("hostname with a private rebinding answer was accepted")
	}
}

func TestRedirectTargetIsRevalidated(t *testing.T) {
	policy := NewPolicy(Options{})
	req := &http.Request{URL: &url.URL{Scheme: "https", Host: "127.0.0.1", Path: "/secret"}}
	if err := policy.CheckRedirect(req, []*http.Request{{URL: &url.URL{Scheme: "https", Host: "example.com"}}}); err == nil {
		t.Fatal("redirect to loopback was accepted")
	}
}

func FuzzValidateHTTPURL(f *testing.F) {
	for _, seed := range []string{
		"https://example.com/hook",
		"http://127.0.0.1",
		"https://[::ffff:127.0.0.1]/",
		"https://2130706433/",
		"file:///etc/passwd",
	} {
		f.Add(seed)
	}
	policy := NewPolicy(Options{})
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = policy.ValidateHTTPURL(raw)
	})
}

func TestPublicPolicyAddressRanges(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		allowed bool
	}{
		{"this network", "0.1.2.3", false},
		{"unspecified", "0.0.0.0", false},
		{"shared address space low", "100.64.0.1", false},
		{"shared address space high", "100.127.255.254", false},
		{"IETF protocol assignments", "192.0.0.8", false},
		{"benchmarking low", "198.18.0.1", false},
		{"benchmarking high", "198.19.255.254", false},
		{"reserved", "240.0.0.1", false},
		{"broadcast", "255.255.255.255", false},
		{"loopback", "127.0.0.1", false},
		{"private", "172.16.5.4", false},
		{"link-local", "169.254.169.254", false},
		{"multicast", "224.0.0.251", false},
		{"IPv6 loopback", "::1", false},
		{"IPv6 unique local", "fd00::1", false},
		{"IPv6 link-local", "fe80::1", false},
		{"IPv4-mapped loopback", "::ffff:127.0.0.1", false},
		{"IPv4-mapped shared address space", "::ffff:100.64.0.1", false},
		{"NAT64 loopback", "64:ff9b::127.0.0.1", false},
		{"NAT64 private", "64:ff9b::10.0.0.1", false},
		{"NAT64 link-local", "64:ff9b::169.254.169.254", false},
		{"NAT64 benchmarking", "64:ff9b::198.18.0.1", false},
		{"local-use NAT64 private", "64:ff9b:1::192.168.1.1", false},
		{"local-use NAT64 shared address space", "64:ff9b:1::100.64.0.1", false},
		{"6to4 loopback", "2002:7f00:1::1", false},
		{"6to4 private", "2002:a00:1::", false},
		{"6to4 link-local", "2002:a9fe:a9fe::1", false},
		{"IPv4-compatible loopback", "::127.0.0.1", false},
		{"IPv4-compatible link-local", "::169.254.169.254", false},
		{"IPv4-compatible public", "::8.8.8.8", false},
		{"IPv4-translated loopback", "::ffff:0:127.0.0.1", false},
		{"IPv4-translated public", "::ffff:0:8.8.8.8", false},
		{"Teredo", "2001:0:4136:e378:8000:63bf:3fff:fdd2", false},
		{"IETF protocol assignments", "2001:1::1", false},
		{"IPv6 benchmarking", "2001:2::1", false},
		{"ORCHIDv2", "2001:20::1", false},
		{"IPv6 documentation", "2001:db8::1", false},
		{"IPv6 documentation 3fff", "3fff::1", false},
		{"site-local", "fec0::1", false},
		{"discard-only", "100::1", false},
		{"local-use NAT64 public", "64:ff9b:1::1.1.1.1", false},
		{"NAT64 outside the /96", "64:ff9b::1:0:0:1", false},
		{"reserved by IETF", "4000::1", false},
		{"reserved low", "::2", false},
		{"public IPv4", "8.8.8.8", true},
		{"public IPv4 near shared address space", "100.63.255.255", true},
		{"public IPv4 after shared address space", "100.128.0.1", true},
		{"public IPv4 near benchmarking", "198.20.0.1", true},
		{"public IPv4 near protocol assignments", "192.0.1.1", true},
		{"public IPv4 below reserved", "223.255.255.254", true},
		{"public IPv6", "2606:4700:4700::1111", true},
		{"public IPv6 short", "2606:4700::1111", true},
		{"public IPv6 after protocol assignments", "2001:200::1", true},
		{"public IPv6 near documentation", "2001:db9::1", true},
		{"IPv4-mapped public", "::ffff:8.8.8.8", true},
		{"NAT64 public", "64:ff9b::8.8.8.8", true},
		{"6to4 public", "2002:808:808::1", true},
		{"6to4 public long form", "2002:0808:0808::1", true},
	}
	policy := NewPolicy(Options{})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.addr)
			if ip == nil {
				t.Fatalf("bad test address %q", tc.addr)
			}
			err := policy.validateIP(ip)
			if tc.allowed && err != nil {
				t.Errorf("%s rejected: %v", tc.addr, err)
			}
			if !tc.allowed && err == nil {
				t.Errorf("%s accepted", tc.addr)
			}
		})
	}
}

func TestAllowedPrivateCoversEmbeddedIPv4(t *testing.T) {
	policy := NewPolicy(Options{AllowedPrivate: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}})
	for _, addr := range []string{"10.1.2.3", "::ffff:10.1.2.3", "64:ff9b::10.1.2.3"} {
		if err := policy.validateIP(net.ParseIP(addr)); err != nil {
			t.Errorf("%s rejected: %v", addr, err)
		}
	}
	if err := policy.validateIP(net.ParseIP("64:ff9b::10.2.0.1")); err == nil {
		t.Error("64:ff9b::10.2.0.1 accepted outside the allowed prefix")
	}
}

func TestAllowedPrivateCoversNonGlobalIPv6(t *testing.T) {
	cases := []struct{ addr, prefix string }{
		{"::127.0.0.1", "::127.0.0.1/128"},
		{"::ffff:0:10.0.0.1", "::ffff:0:0:0/96"},
		{"2001::1", "2001::/32"},
		{"fec0::1", "fec0::/10"},
		{"100::1", "100::/64"},
		{"64:ff9b:1::10.0.0.1", "64:ff9b:1::/48"},
		{"2001:db8::1", "2001:db8::/32"},
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.addr)
		if err := NewPolicy(Options{}).validateIP(ip); err == nil {
			t.Errorf("%s accepted without an allowlist", tc.addr)
		}
		allowed := NewPolicy(Options{AllowedPrivate: []netip.Prefix{netip.MustParsePrefix(tc.prefix)}})
		if err := allowed.validateIP(ip); err != nil {
			t.Errorf("%s rejected with %s allowed: %v", tc.addr, tc.prefix, err)
		}
		if err := DevelopmentPolicy().validateIP(ip); err != nil {
			t.Errorf("%s rejected by the development policy: %v", tc.addr, err)
		}
	}
}

// recordingDialer records each address it is asked to dial and fails the dial.
type recordingDialer struct{ dialed []string }

func (d *recordingDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	d.dialed = append(d.dialed, address)
	return nil, errors.New("dial disabled in tests")
}

func TestResolvedAddressRangesAreChecked(t *testing.T) {
	dialer := &recordingDialer{}
	policy := NewPolicy(Options{Dialer: dialer, Resolver: staticResolver{
		"shared.example": {net.ParseIP("203.0.113.10"), net.ParseIP("100.64.0.1")},
		"nat64.example":  {net.ParseIP("64:ff9b::127.0.0.1")},
		"6to4.example":   {net.ParseIP("2002:a00:1::")},
		"public.example": {net.ParseIP("203.0.113.10"), net.ParseIP("64:ff9b::8.8.8.8")},
	}})
	for _, host := range []string{"shared.example", "nat64.example", "6to4.example"} {
		if err := policy.ValidateHost(context.Background(), host); err == nil {
			t.Errorf("%s accepted", host)
		}
		_, _ = policy.DialContext(context.Background(), "tcp", net.JoinHostPort(host, "443"))
	}
	if len(dialer.dialed) != 0 {
		t.Errorf("dialed %v", dialer.dialed)
	}
	if err := policy.ValidateHost(context.Background(), "public.example"); err != nil {
		t.Errorf("public.example rejected: %v", err)
	}
	_, _ = policy.DialContext(context.Background(), "tcp", "public.example:443")
	if want := []string{"203.0.113.10:443", "[64:ff9b::808:808]:443"}; !slices.Equal(dialer.dialed, want) {
		t.Errorf("dialed %v, want %v", dialer.dialed, want)
	}
}

func TestRedirectTargetRangesAreRevalidated(t *testing.T) {
	policy := NewPolicy(Options{Resolver: staticResolver{
		"nat64.example": {net.ParseIP("64:ff9b::169.254.169.254")},
	}})
	via := []*http.Request{{URL: &url.URL{Scheme: "https", Host: "example.com"}}}
	for _, host := range []string{"100.64.0.1", "[64:ff9b::a00:1]", "nat64.example"} {
		req := &http.Request{URL: &url.URL{Scheme: "https", Host: host, Path: "/"}}
		if err := policy.CheckRedirect(req, via); err == nil {
			t.Errorf("redirect to %s accepted", host)
		}
	}
}
