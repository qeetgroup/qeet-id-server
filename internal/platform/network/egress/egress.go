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

type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

type dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type Options struct {
	Resolver        Resolver
	AllowedPrivate  []netip.Prefix
	AllowInsecure   bool
	AllowAllPrivate bool
	Dialer          dialer
}

type Policy struct {
	resolver        Resolver
	allowedPrivate  []netip.Prefix
	allowInsecure   bool
	allowAllPrivate bool
	dialer          dialer
}

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
	}
}

func PublicPolicy(optional ...*Policy) *Policy {
	if len(optional) > 0 && optional[0] != nil {
		return optional[0]
	}
	return NewPolicy(Options{})
}

func DevelopmentPolicy() *Policy {
	return NewPolicy(Options{AllowInsecure: true, AllowAllPrivate: true})
}

func (p *Policy) ValidateHTTPURL(raw string) (*url.URL, error) {
	return p.validateURL(raw, map[string]struct{}{"https": {}, "http": {}})
}

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
	for _, prefix := range p.allowedPrivate {
		if prefix.Contains(addr) {
			return nil
		}
	}
	if p.allowAllPrivate {
		return nil
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return fmt.Errorf("outbound destination address %s is not public", addr)
	}
	return nil
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

func (p *Policy) ValidateHost(ctx context.Context, host string) error {
	_, err := p.resolveAllowed(ctx, host)
	return err
}

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

func (p *Policy) CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many outbound redirects")
	}
	_, err := p.ValidateHTTPURL(req.URL.String())
	if err != nil {
		return err
	}
	_, err = p.resolveAllowed(req.Context(), req.URL.Hostname())
	return err
}

func (p *Policy) HTTPClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = p.DialContext
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
