// Package egress provides the shared outbound network boundary for tenant-
// configured integrations. It rejects destinations that can reach the local
// host, private networks, link-local services, or other non-public addresses.
package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Resolver looks up a host's IP addresses; *net.Resolver satisfies it.
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

type dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Options configures NewPolicy. AllowedPrivate lists non-public prefixes that
// are still reachable, AllowInsecure permits http and ldap, and AllowAllPrivate
// skips the address check. A nil Resolver or Dialer uses the net defaults.
type Options struct {
	Resolver        Resolver
	AllowedPrivate  []netip.Prefix
	AllowInsecure   bool
	AllowAllPrivate bool
	Dialer          dialer
	// ProxyURL routes outbound HTTP through an operator-run forward proxy.
	// Ambient HTTPS_PROXY is deliberately ignored: a proxy resolves the
	// destination itself, so it decides what this service can reach. That has
	// to be a deployment decision, not something the environment can turn on.
	ProxyURL *url.URL
}

// Policy decides which outbound destinations are allowed, and builds HTTP
// clients and dialers that enforce it.
type Policy struct {
	resolver        Resolver
	allowedPrivate  []netip.Prefix
	allowInsecure   bool
	allowAllPrivate bool
	dialer          dialer
	proxyURL        *url.URL
}

// NewPolicy returns a Policy configured by options.
func NewPolicy(options Options) *Policy {
	resolver := options.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	baseDialer := options.Dialer
	if baseDialer == nil {
		baseDialer = &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	}
	return &Policy{
		resolver:        resolver,
		allowedPrivate:  append([]netip.Prefix(nil), options.AllowedPrivate...),
		allowInsecure:   options.AllowInsecure,
		allowAllPrivate: options.AllowAllPrivate,
		dialer:          baseDialer,
		proxyURL:        options.ProxyURL,
	}
}

// PublicPolicy returns optional[0] if given and non-nil, else the default
// policy: https and ldaps to public addresses only.
func PublicPolicy(optional ...*Policy) *Policy {
	if len(optional) > 0 && optional[0] != nil {
		return optional[0]
	}
	return NewPolicy(Options{})
}

// DevelopmentPolicy also allows http, ldap and non-public addresses, for local
// development.
func DevelopmentPolicy() *Policy {
	return NewPolicy(Options{AllowInsecure: true, AllowAllPrivate: true})
}

// ValidateHTTPURL parses raw and checks it is an allowed http(s) destination:
// absolute, without userinfo or a fragment, not a local or ambiguous numeric
// host, and not a disallowed IP literal. Host names are not resolved here.
func (p *Policy) ValidateHTTPURL(raw string) (*url.URL, error) {
	return p.validateURL(raw, map[string]struct{}{"https": {}, "http": {}})
}

// ValidateLDAPURL is ValidateHTTPURL for ldap and ldaps URLs.
func (p *Policy) ValidateLDAPURL(raw string) (*url.URL, error) {
	return p.validateURL(raw, map[string]struct{}{"ldaps": {}, "ldap": {}})
}

func (p *Policy) validateURL(raw string, schemes map[string]struct{}) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !u.IsAbs() || u.Hostname() == "" {
		return nil, errors.New("outbound destination must be an absolute URL")
	}
	if u.User != nil || u.Fragment != "" {
		return nil, errors.New("outbound destination cannot contain userinfo or a fragment")
	}
	scheme := strings.ToLower(u.Scheme)
	if _, ok := schemes[scheme]; !ok {
		return nil, fmt.Errorf("outbound destination scheme %q is not allowed", scheme)
	}
	if (scheme == "http" || scheme == "ldap") && !p.allowInsecure {
		return nil, fmt.Errorf("outbound destination scheme %q is disabled", scheme)
	}
	if port := u.Port(); port != "" {
		parsed, err := strconv.Atoi(port)
		if err != nil || parsed < 1 || parsed > 65535 {
			return nil, errors.New("outbound destination has an invalid port")
		}
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return nil, errors.New("outbound destination resolves to a local hostname")
	}
	if isAmbiguousNumericHost(host) {
		return nil, errors.New("outbound destination uses an ambiguous numeric host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if err := p.validateIP(ip); err != nil {
			return nil, err
		}
	}
	return u, nil
}

func isAmbiguousNumericHost(host string) bool {
	if strings.HasPrefix(host, "0x") {
		return true
	}
	if host == "" {
		return false
	}
	for _, r := range host {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func (p *Policy) validateIP(ip net.IP) error {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return errors.New("outbound destination resolved to an invalid address")
	}
	addr = addr.Unmap()
	embedded, hasEmbedded := embeddedIPv4(addr)
	for _, prefix := range p.allowedPrivate {
		if prefix.Contains(addr) || (hasEmbedded && prefix.Contains(embedded)) {
			return nil
		}
	}
	if p.allowAllPrivate {
		return nil
	}
	if !isPublic(addr) || (hasEmbedded && !isPublic(embedded)) {
		return fmt.Errorf("outbound destination address %s is not public", addr)
	}
	return nil
}

// nonPublicIPv4 lists IPv4 ranges that are not publicly routable and that the
// netip predicates used by isPublic do not cover.
var nonPublicIPv4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),     // "this network"
	netip.MustParsePrefix("100.64.0.0/10"), // shared address space
	netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),   // reserved, including broadcast
}

// IPv6 prefixes whose addresses carry an IPv4 destination.
var (
	nat64WellKnown = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour      = netip.MustParsePrefix("2002::/16")
)

// globalUnicast is the only IPv6 range treated as public, less nonPublicIPv6.
var globalUnicast = netip.MustParsePrefix("2000::/3")

// nonPublicIPv6 lists the parts of globalUnicast that are not publicly routable.
var nonPublicIPv6 = []netip.Prefix{
	netip.MustParsePrefix("2001::/23"),     // IETF protocol assignments, including Teredo
	netip.MustParsePrefix("2001:db8::/32"), // documentation
	netip.MustParsePrefix("3fff::/20"),     // documentation
}

// isPublic reports whether addr is publicly routable. For a NAT64 or 6to4
// address it judges only the IPv6 prefix; validateIP checks the IPv4 address
// the prefix carries.
func isPublic(addr netip.Addr) bool {
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	if addr.Is6() {
		return isPublicIPv6(addr)
	}
	for _, prefix := range nonPublicIPv4 {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

// isPublicIPv6 reports whether addr is global unicast outside nonPublicIPv6.
// The well-known NAT64 prefix lies outside global unicast but is allowed, so a
// host on an IPv6-only network with DNS64 can still reach public IPv4 targets.
func isPublicIPv6(addr netip.Addr) bool {
	if nat64WellKnown.Contains(addr) {
		return true
	}
	if !globalUnicast.Contains(addr) {
		return false
	}
	for _, prefix := range nonPublicIPv6 {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

// embeddedIPv4 returns the IPv4 address carried by a well-known-prefix NAT64 or
// a 6to4 address, so the IPv4 rules apply to it. NAT64 addresses use the /96
// layout, with the IPv4 address in the last four bytes.
func embeddedIPv4(addr netip.Addr) (netip.Addr, bool) {
	if !addr.Is6() {
		return netip.Addr{}, false
	}
	b := addr.As16()
	switch {
	case nat64WellKnown.Contains(addr):
		return netip.AddrFrom4([4]byte(b[12:16])), true
	case sixToFour.Contains(addr):
		return netip.AddrFrom4([4]byte(b[2:6])), true
	}
	return netip.Addr{}, false
}

func (p *Policy) resolveAllowed(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if err := p.validateIP(ip); err != nil {
			return nil, err
		}
		return []net.IP{ip}, nil
	}
	ips, err := p.resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve outbound destination: %w", err)
	}
	if len(ips) == 0 {
		return nil, errors.New("outbound destination resolved to no addresses")
	}
	for _, ip := range ips {
		if err := p.validateIP(ip); err != nil {
			return nil, err
		}
	}
	return ips, nil
}

// ValidateHost resolves host and returns an error unless every address it
// resolves to is allowed.
func (p *Policy) ValidateHost(ctx context.Context, host string) error {
	_, err := p.resolveAllowed(ctx, host)
	return err
}

// DialContext resolves address, refuses it unless every resolved IP is allowed,
// then dials those IPs in turn, so the checked address is the one connected to.
func (p *Policy) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("parse outbound address: %w", err)
	}
	ips, err := p.resolveAllowed(ctx, host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range ips {
		conn, dialErr := p.dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	return nil, lastErr
}

// CheckRedirect is an http.Client CheckRedirect that stops after 5 redirects
// and validates each target, resolving its host unless a proxy is configured.
func (p *Policy) CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many outbound redirects")
	}
	_, err := p.ValidateHTTPURL(req.URL.String())
	if err != nil {
		return err
	}
	if p.proxyURL != nil {
		return nil
	}
	_, err = p.resolveAllowed(req.Context(), req.URL.Hostname())
	return err
}

// HTTPClient returns a client with timeout that dials only allowed addresses,
// or sends everything through Options.ProxyURL when set; ambient proxy
// variables are ignored.
func (p *Policy) HTTPClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if p.proxyURL != nil {
		// The proxy opens the destination connection, so pinning here would only
		// check the proxy's own, usually private, address. URLs are still validated;
		// the proxy enforces the address policy.
		transport.Proxy = http.ProxyURL(p.proxyURL)
	} else {
		transport.Proxy = nil
		transport.DialContext = p.DialContext
	}
	return &http.Client{
		Timeout:       timeout,
		Transport:     transport,
		CheckRedirect: p.CheckRedirect,
	}
}

// NetDialer returns a dialer suitable for libraries that resolve hosts
// internally. ControlContext validates the concrete address selected by the
// resolver immediately before the socket is opened.
func (p *Policy) NetDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		ControlContext: func(_ context.Context, _, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return errors.New("outbound dial address was not resolved")
			}
			return p.validateIP(ip)
		},
	}
}
