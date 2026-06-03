// Package hibp implements breached-password detection against the Have I Been
// Pwned "Pwned Passwords" range API using k-anonymity, so the plaintext
// password never leaves the process.
//
// The protocol: SHA-1 the UTF-8 password and uppercase the 40-char hex digest.
// Only the first 5 hex chars (the PREFIX) are sent to the API; the remaining 35
// (the SUFFIX) are matched locally against the response. The request carries
// `Add-Padding: true` so the response length doesn't leak how many hashes share
// the prefix. The response is CRLF-separated `SUFFIX:COUNT` lines; a match with
// COUNT above the configured threshold means the password is known-breached.
//
// The Checker is OFF by default (constructed only when enabled) and FAIL-OPEN:
// any transport error, timeout, or non-200 status logs a warning and reports
// not-breached, so a HIBP outage can never block a password change. Wiring is
// in cmd/server/main.go; the validation hooks live in the password-setting
// flows (auth signup, recovery reset, invite accept, user set-password).
package hibp

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is the public Pwned Passwords range API. Overridable for tests.
const DefaultBaseURL = "https://api.pwnedpasswords.com"

// defaultTimeout bounds a single range lookup so a slow HIBP never stalls a
// password change; on timeout the Checker fails open (see Pwned).
const defaultTimeout = 3 * time.Second

// Checker queries the HIBP range API. The zero value is not usable; build one
// with New. A nil *Checker is a valid no-op (Pwned reports not-breached) so
// callers can hold an optional, possibly-disabled checker without nil guards.
type Checker struct {
	client   *http.Client
	baseURL  string
	minCount int
}

// New builds a Checker. A nil client gets a default with a short timeout; an
// empty baseURL defaults to DefaultBaseURL. minCount is the breach-sighting
// threshold at or above which a password is treated as breached (minimum 1).
func New(client *http.Client, baseURL string, minCount int) *Checker {
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if minCount < 1 {
		minCount = 1
	}
	return &Checker{client: client, baseURL: strings.TrimRight(baseURL, "/"), minCount: minCount}
}

// Pwned reports whether password appears in known breach corpora and, if so,
// how many times. Only the 5-char SHA-1 prefix is sent to the API. It is
// FAIL-OPEN: on any error (nil checker, request build, transport, non-200,
// body read) it returns (false, 0, err) with a logged warning — callers that
// want fail-open behaviour should ignore err for the allow/deny decision and
// rely on the false. PwnedAllowOnError wraps that pattern.
func (c *Checker) Pwned(ctx context.Context, password string) (breached bool, count int, err error) {
	if c == nil {
		return false, 0, nil
	}

	sum := sha1.Sum([]byte(password)) // #nosec G401 -- HIBP protocol mandates SHA-1; not used for security.
	digest := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := digest[:5], digest[5:]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/range/"+prefix, nil)
	if err != nil {
		return false, 0, err
	}
	// Add-Padding pads the response with random zero-count lines so its length
	// reveals nothing about the real number of matching suffixes.
	req.Header.Set("Add-Padding", "true")

	resp, err := c.client.Do(req)
	if err != nil {
		return false, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Drain a little so the connection can be reused, then report the status.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 512))
		return false, 0, fmt.Errorf("hibp: unexpected status %s", resp.Status)
	}

	count, err = matchSuffix(resp.Body, suffix)
	if err != nil {
		return false, 0, err
	}
	return count >= c.minCount, count, nil
}

// PwnedAllowOnError is the fail-open convenience used by the password-setting
// flows: it returns whether the password is breached, swallowing any error
// (logging a warning) so a HIBP outage never blocks the user. A nil checker
// always returns false (the feature is disabled).
func (c *Checker) PwnedAllowOnError(ctx context.Context, password string) bool {
	breached, _, err := c.Pwned(ctx, password)
	if err != nil {
		// FAIL-OPEN: never block a password change on a third-party outage.
		slog.Warn("breached-password check failed; allowing password (fail-open)", "err", err)
		return false
	}
	return breached
}

// matchSuffix scans CRLF-separated `SUFFIX:COUNT` lines for a case-insensitive
// match on want and returns its count (0 if absent). Padding lines carry
// count 0 and are ignored by callers via the minCount threshold.
func matchSuffix(body io.Reader, want string) (int, error) {
	sc := bufio.NewScanner(body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		sfx, cnt, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(sfx), want) {
			continue
		}
		n, perr := strconv.Atoi(strings.TrimSpace(cnt))
		if perr != nil {
			return 0, fmt.Errorf("hibp: bad count %q: %w", cnt, perr)
		}
		return n, nil
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, nil
}

// ErrBreached is the sentinel a validation layer can compare against; the
// user-facing 422 detail deliberately omits the sighting count.
var ErrBreached = errors.New("password has appeared in known data breaches")
