package hibp

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// roundTripFunc is a fake http.RoundTripper that captures the outbound request
// and returns a canned response, so tests never touch the network.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// suffixOf returns the uppercase 35-char SHA-1 suffix of a password — the part
// the API echoes back. Used to build canned range responses.
func suffixOf(pw string) string {
	s := sha1.Sum([]byte(pw))
	return strings.ToUpper(hex.EncodeToString(s[:]))[5:]
}

// fakeClient wires a RoundTripper into an *http.Client and records every
// request path it sees, so tests can assert the k-anonymity contract.
func fakeClient(rt roundTripFunc) *http.Client { return &http.Client{Transport: rt} }

func textResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func TestPwned_BreachedSuffixRejected(t *testing.T) {
	const pw = "password123"
	// The fake range body contains our password's suffix with a high count,
	// plus an unrelated line. Lines are CRLF-separated like the real API.
	body := "00000000000000000000000000000000000:3\r\n" +
		suffixOf(pw) + ":42\r\n"
	c := New(fakeClient(func(_ *http.Request) (*http.Response, error) {
		return textResponse(http.StatusOK, body), nil
	}), "https://hibp.test", 1)

	breached, count, err := c.Pwned(context.Background(), pw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !breached {
		t.Error("password present in range body should be reported breached")
	}
	if count != 42 {
		t.Errorf("count = %d, want 42", count)
	}
}

func TestPwned_AbsentSuffixPasses(t *testing.T) {
	body := "ABCDEF0123456789ABCDEF0123456789ABC:9\r\n"
	c := New(fakeClient(func(_ *http.Request) (*http.Response, error) {
		return textResponse(http.StatusOK, body), nil
	}), "https://hibp.test", 1)

	breached, count, err := c.Pwned(context.Background(), "a-passphrase-not-in-the-body")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if breached {
		t.Error("password absent from range body must not be reported breached")
	}
	if count != 0 {
		t.Errorf("count = %d, want 0", count)
	}
}

func TestPwned_PaddingLineWithZeroCountIgnored(t *testing.T) {
	const pw = "password123"
	// Add-Padding can return the matching suffix with count 0 (a padding line);
	// such a sighting must not count as breached.
	body := suffixOf(pw) + ":0\r\n"
	c := New(fakeClient(func(_ *http.Request) (*http.Response, error) {
		return textResponse(http.StatusOK, body), nil
	}), "https://hibp.test", 1)

	breached, count, err := c.Pwned(context.Background(), pw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if breached {
		t.Error("a count-0 padding line must not be treated as breached")
	}
	if count != 0 {
		t.Errorf("count = %d, want 0", count)
	}
}

func TestPwned_RespectsMinCountThreshold(t *testing.T) {
	const pw = "password123"
	body := suffixOf(pw) + ":5\r\n"
	// Threshold 10 → a 5-sighting password is below it, so not rejected.
	c := New(fakeClient(func(_ *http.Request) (*http.Response, error) {
		return textResponse(http.StatusOK, body), nil
	}), "https://hibp.test", 10)

	breached, count, err := c.Pwned(context.Background(), pw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if breached {
		t.Error("count below min threshold must not be reported breached")
	}
	if count != 5 {
		t.Errorf("count = %d, want 5", count)
	}
}

func TestPwned_RequestContractAndKAnonymity(t *testing.T) {
	const pw = "password123" // prefix CBFDA (computed via crypto/sha1)
	var gotPath, gotPadding, gotRawQuery, gotBodyURL string
	c := New(fakeClient(func(r *http.Request) (*http.Response, error) {
		gotPath = r.URL.Path
		gotRawQuery = r.URL.RawQuery
		gotPadding = r.Header.Get("Add-Padding")
		gotBodyURL = r.URL.String()
		return textResponse(http.StatusOK, suffixOf(pw)+":7\r\n"), nil
	}), "https://hibp.test", 1)

	if _, _, err := c.Pwned(context.Background(), pw); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Path must be /range/<5 uppercase hex>, with the Add-Padding header set.
	if gotPath != "/range/CBFDA" {
		t.Errorf("request path = %q, want /range/CBFDA", gotPath)
	}
	if gotPadding != "true" {
		t.Errorf("Add-Padding header = %q, want true", gotPadding)
	}

	// k-anonymity: the plaintext, and even the full digest/suffix, must never
	// appear anywhere in the outbound request — only the 5-char prefix.
	full := strings.ToUpper(hex.EncodeToString(func() []byte { s := sha1.Sum([]byte(pw)); return s[:] }()))
	for label, hay := range map[string]string{"path": gotPath, "query": gotRawQuery, "url": gotBodyURL} {
		if strings.Contains(hay, pw) {
			t.Errorf("plaintext password leaked in request %s: %q", label, hay)
		}
		if strings.Contains(strings.ToUpper(hay), suffixOf(pw)) {
			t.Errorf("SHA-1 suffix leaked in request %s: %q", label, hay)
		}
		if strings.Contains(strings.ToUpper(hay), full) {
			t.Errorf("full SHA-1 digest leaked in request %s: %q", label, hay)
		}
	}
}

func TestPwned_CaseInsensitiveSuffixMatch(t *testing.T) {
	const pw = "password123"
	// Real responses are uppercase; assert we still match if a mirror returns
	// lowercase suffixes.
	body := strings.ToLower(suffixOf(pw)) + ":11\r\n"
	c := New(fakeClient(func(_ *http.Request) (*http.Response, error) {
		return textResponse(http.StatusOK, body), nil
	}), "https://hibp.test", 1)

	breached, _, err := c.Pwned(context.Background(), pw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !breached {
		t.Error("suffix compare must be case-insensitive")
	}
}

func TestPwned_FailOpenOnTransportError(t *testing.T) {
	c := New(fakeClient(func(_ *http.Request) (*http.Response, error) {
		return nil, errors.New("dial tcp: connection refused")
	}), "https://hibp.test", 1)

	breached, count, err := c.Pwned(context.Background(), "password123")
	if err == nil {
		t.Error("Pwned should surface the transport error to its caller")
	}
	if breached || count != 0 {
		t.Errorf("on error want (false,0), got (%v,%d)", breached, count)
	}

	// The fail-open helper must swallow the error and allow the password.
	if c.PwnedAllowOnError(context.Background(), "password123") {
		t.Error("PwnedAllowOnError must allow (return false) on a transport error")
	}
}

func TestPwned_FailOpenOnNon200(t *testing.T) {
	c := New(fakeClient(func(_ *http.Request) (*http.Response, error) {
		return textResponse(http.StatusServiceUnavailable, "upstream down"), nil
	}), "https://hibp.test", 1)

	breached, _, err := c.Pwned(context.Background(), "password123")
	if err == nil {
		t.Error("non-200 status should be returned as an error")
	}
	if breached {
		t.Error("non-200 must not report breached")
	}
	if c.PwnedAllowOnError(context.Background(), "password123") {
		t.Error("PwnedAllowOnError must allow (return false) on a non-200 status")
	}
}

func TestPwned_NilCheckerIsNoOp(t *testing.T) {
	var c *Checker // feature disabled
	breached, count, err := c.Pwned(context.Background(), "anything")
	if err != nil || breached || count != 0 {
		t.Errorf("nil checker must be a no-op, got (%v,%d,%v)", breached, count, err)
	}
	if c.PwnedAllowOnError(context.Background(), "anything") {
		t.Error("nil checker PwnedAllowOnError must return false (allow)")
	}
}

func TestNew_Defaults(t *testing.T) {
	c := New(nil, "", 0)
	if c.client == nil || c.client.Timeout == 0 {
		t.Error("nil client should default with a timeout")
	}
	if c.baseURL != DefaultBaseURL {
		t.Errorf("baseURL = %q, want %q", c.baseURL, DefaultBaseURL)
	}
	if c.minCount != 1 {
		t.Errorf("minCount = %d, want clamped to 1", c.minCount)
	}
	// Trailing slash trimmed so the path join stays clean.
	if got := New(nil, "https://x.test/", 1).baseURL; got != "https://x.test" {
		t.Errorf("baseURL trailing slash not trimmed: %q", got)
	}
}
