package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const testRelayKey = "relay-key-for-tests-0123456789abcdef"

// A relay presenting a valid key names the person's address; anything else
// (no key, a wrong key, no keys configured, an unreadable address) is judged
// by the usual rules, so a direct caller can't pick the address it is judged by.
func TestClientIPTrustsOnlyAKeyedRelay(t *testing.T) {
	t.Cleanup(func() { SetRelayKeys(nil); SetTrustedProxyHops(0) })
	request := func(key, claimed string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "10.0.0.5:5555" // the relay's own address
		if key != "" {
			r.Header.Set(RelayKeyHeader, key)
		}
		if claimed != "" {
			r.Header.Set(RelayClientIPHeader, claimed)
		}
		return r
	}

	SetRelayKeys(nil)
	if got := ClientIP(request(testRelayKey, "198.51.100.7")); got != "10.0.0.5" {
		t.Fatalf("no keys configured: ClientIP = %q, want the relay's address", got)
	}

	SetRelayKeys([]string{"old-relay-key-0123456789abcdefghij", testRelayKey})
	for name, c := range map[string]struct{ key, claimed, want string }{
		"a valid key":                         {testRelayKey, "198.51.100.7", "198.51.100.7"},
		"an IPv4-mapped address":              {testRelayKey, "::ffff:198.51.100.7", "198.51.100.7"},
		"a wrong key":                         {"guessed-relay-key-0123456789abcdefg", "198.51.100.7", "10.0.0.5"},
		"no key":                              {"", "198.51.100.7", "10.0.0.5"},
		"a key but an unreadable address":     {testRelayKey, "not-an-ip", "10.0.0.5"},
		"a key but no address":                {testRelayKey, "", "10.0.0.5"},
		"the other configured key (rotation)": {"old-relay-key-0123456789abcdefghij", "203.0.113.9", "203.0.113.9"},
	} {
		if got := ClientIP(request(c.key, c.claimed)); got != c.want {
			t.Errorf("%s: ClientIP = %q, want %q", name, got, c.want)
		}
	}

	// A forged X-Forwarded-For doesn't help a caller without the key either.
	SetTrustedProxyHops(1)
	r := request("", "198.51.100.7")
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 10.0.0.9")
	if got := ClientIP(r); got != "10.0.0.9" {
		t.Fatalf("without a key: ClientIP = %q, want the proxy-appended address", got)
	}
}
