// Package hibp checks passwords against the Have I Been Pwned range API with
// k-anonymity: only the first 5 hex characters of the password's SHA-1 are sent
// and the rest is matched locally. The check is off unless enabled and fails
// open (see PwnedAllowOnError), so an outage never blocks a password change.
package hibp

import (
	"bufio"
	"context"
	"crypto/sha1" // #nosec G505 -- the HIBP range API is keyed by SHA-1
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// DefaultBaseURL is the public Pwned Passwords range API. Overridable for tests.
const DefaultBaseURL = "https://api.pwnedpasswords.com"

// defaultTimeout bounds a single range lookup so a slow HIBP never stalls a
// password change; on timeout PwnedAllowOnError fails open.
const defaultTimeout = 3 * time.Second

// allowedOnError counts the passwords let through because the provider could
// not give an answer (fail-open), so an outage — or a misconfigured
// BREACHED_PASSWORD_API_URL — shows up on /metrics instead of only in logs.
var allowedOnError = promauto.NewCounter(prometheus.CounterOpts{
	Name: "breached_password_check_allowed_on_error_total",
	Help: "Breached-password checks that could not reach the provider and allowed the password (fail-open).",
})

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

// Pwned reports whether password has been seen in at least minCount breaches,
// and how many times. Only the 5-character SHA-1 prefix is sent. On any failure
// it returns (false, 0, err); a nil Checker returns (false, 0, nil).
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

// PwnedAllowOnError reports whether password is breached, failing open: an
// error is logged, counted in breached_password_check_allowed_on_error_total and
// reported as not breached. A nil Checker returns false without counting.
func (c *Checker) PwnedAllowOnError(ctx context.Context, password string) bool {
	breached, _, err := c.Pwned(ctx, password)
	if err != nil {
		// FAIL-OPEN: never block a password change on a third-party outage.
		allowedOnError.Inc()
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

// ErrBreached reports a password found in known breaches. Its message carries
// no sighting count.
var ErrBreached = errors.New("password has appeared in known data breaches")
