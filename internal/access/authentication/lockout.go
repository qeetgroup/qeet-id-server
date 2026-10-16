package auth

// Sign-in lockout: brute-force and spraying protection for password sign-in.
//
// Failed password sign-ins are counted three ways, all in PostgreSQL so every
// API replica sees the same counts:
//
//  1. Per account and source network — the lock a tenant configures
//     (threshold, window, duration; see Lockout). Failures from a network
//     that does not control the account lock it for that network only, so a
//     stranger cannot lock the owner out.
//  2. Per account alone, at AccountMultiplier × the threshold — failures
//     spread over many networks still lock the account everywhere, so a
//     distributed attack stays bounded.
//  3. Per source network across distinct accounts — a network that fails
//     against SourceAccounts accounts within SourceWindow is refused password
//     sign-in for SourceBlock, so broad-and-shallow spraying (a few guesses
//     against many accounts) is bounded and reported.
//
// The account is the lowercased address whether or not an account has it, so
// an unknown address is counted, locked and answered exactly like a real one.
// The source network is the client IP as httpx.ClientIP derives it behind
// trusted proxies: an IPv4 address, or the /64 an IPv6 address belongs to.
// A failure is forgotten once the window passes with no new failure; a lock
// or throttle that has run its course starts the count afresh; a successful
// sign-in clears the account's count and its count from that network.
//
// The counters live in the same database the password check and the session
// need, so when they cannot be read or written the sign-in fails closed: it is
// refused with errs.ErrAuthSignInUnavailable — the same answer whatever the
// password and whether the address has an account — and counted in
// sign_in_lockout_unavailable_total (ADR-0016). The per-request rate
// limiter's own store-error behaviour is a separate decision (ADR-0007) and is
// not affected.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication/dbgen"
	password "github.com/qeetgroup/qeet-id-server/internal/platform/crypto/encryption"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// The counters a lock or throttle can come from, as named in signals and metrics.
const (
	CounterAccountNetwork = "account_network"
	CounterAccount        = "account"
	CounterSource         = "source"
)

// Stages of a lockout evaluation that touch the counter store, as named in
// sign_in_lockout_unavailable_total.
const (
	stageSettings = "settings"
	stageCheck    = "check"
	stageRecord   = "record"
	stageClear    = "clear"
)

var (
	lockoutUnavailable = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sign_in_lockout_unavailable_total",
		Help: "Password sign-ins refused because the lockout could not be evaluated (its settings or counters could not be read or written), by stage. The lockout fails closed.",
	}, []string{"stage"})
	lockoutsSet = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sign_in_lockouts_total",
		Help: "Sign-in locks set, by the counter that tripped (account_network, account).",
	}, []string{"counter"})
	sourceThrottles = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sign_in_source_throttles_total",
		Help: "Source networks throttled for failing password sign-in against too many distinct accounts (spraying).",
	})
)

func init() {
	// Publish every series at zero so an alert can rate() it from the start.
	for _, stage := range []string{stageSettings, stageCheck, stageRecord, stageClear} {
		lockoutUnavailable.WithLabelValues(stage)
	}
	for _, counter := range []string{CounterAccountNetwork, CounterAccount} {
		lockoutsSet.WithLabelValues(counter)
	}
}

// lockoutStoreTimeout bounds each lockout store call. The calls are detached
// from the request's cancellation, so a caller hanging up mid-attempt cannot
// keep a failure from being counted.
const lockoutStoreTimeout = 5 * time.Second

// Lockout is the lock a password sign-in is held to: Threshold failures from
// one network, each within Window of the last, lock the account for that
// network for Duration.
type Lockout struct {
	Threshold int
	Window    time.Duration
	Duration  time.Duration
}

// LockoutSource returns the lockout a tenant applies (uuid.Nil: no tenant —
// the platform defaults). Satisfied in bootstrap by the auth-policy service;
// a func so auth doesn't import authpolicy.
type LockoutSource func(ctx context.Context, tenantID uuid.UUID) (Lockout, error)

// LockoutConfig is the platform-wide part of the sign-in protections (env).
type LockoutConfig struct {
	// Defaults applies when no LockoutSource is wired.
	Defaults Lockout
	// AccountMultiplier sets the per-account cap: Threshold × AccountMultiplier
	// failures from any mix of networks lock the account everywhere.
	AccountMultiplier int
	// A source network that fails against SourceAccounts distinct accounts
	// within SourceWindow is refused password sign-in for SourceBlock.
	SourceAccounts int
	SourceWindow   time.Duration
	SourceBlock    time.Duration
}

// DefaultLockoutConfig: five failures within fifteen minutes lock for fifteen
// minutes; twenty failures from any networks lock the account; a network
// failing against thirty accounts within fifteen minutes is throttled for
// fifteen minutes.
func DefaultLockoutConfig() LockoutConfig {
	return LockoutConfig{
		Defaults:          Lockout{Threshold: 5, Window: 15 * time.Minute, Duration: 15 * time.Minute},
		AccountMultiplier: 4,
		SourceAccounts:    30,
		SourceWindow:      15 * time.Minute,
		SourceBlock:       15 * time.Minute,
	}
}

// SetLockoutConfig sets the platform-wide lockout configuration (from
// LOGIN_LOCKOUT_* and LOGIN_SPRAY_*). Called from internal/bootstrap/dependencies.go.
func (s *Service) SetLockoutConfig(c LockoutConfig) { s.lockout = c }

// SetLockoutSource wires the per-tenant lockout settings. Called from
// internal/bootstrap/dependencies.go.
func (s *Service) SetLockoutSource(f LockoutSource) { s.lockoutSource = f }

// AccountLock describes a lock at the moment it is set, for security monitoring.
type AccountLock struct {
	Email       string // the account: the lowercased address
	Network     string // the source network whose failure set the lock ("" unknown)
	Counter     string // CounterAccountNetwork or CounterAccount
	Reason      string
	Failures    int
	Threshold   int
	Window      time.Duration
	LockedUntil time.Time
}

// SourceThrottle describes a source network at the moment it is throttled.
type SourceThrottle struct {
	Network        string
	Accounts       []string // the distinct accounts it failed against within the window
	Window         time.Duration
	ThrottledUntil time.Time
	Reason         string
}

// signInAttempt is one password sign-in as the lockout sees it.
type signInAttempt struct {
	email   string
	network string
	lockout Lockout
	now     time.Time
}

// SignInTenant resolves which tenant's authentication policy governs a
// sign-in attempt, before the credential is verified: the tenant of the OAuth
// client a hosted login is serving, when the attempt names one; otherwise none
// (uuid.Nil — the platform defaults). An unknown client also gets none.
//
// It deliberately never uses the account's own tenant: before the credential
// is verified, a setting that depended on whether — and where — the address
// has an account would tell an observer exactly that. Once the credential is
// verified, the account's home tenant may be used for decisions only its
// owner can observe.
func (s *Service) SignInTenant(ctx context.Context, clientID string) (uuid.UUID, error) {
	if clientID == "" {
		return uuid.Nil, nil
	}
	tenantID, err := s.q.GetClientTenant(ctx, clientID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, nil
	}
	return tenantID, err
}

// newSignInAttempt resolves the lockout an attempt is held to.
func (s *Service) newSignInAttempt(ctx context.Context, in SignInAttempt) (signInAttempt, error) {
	a := signInAttempt{
		email:   strings.ToLower(strings.TrimSpace(in.Email)),
		network: SourceNetwork(in.IP),
		lockout: s.lockout.Defaults,
		// Microseconds, as PostgreSQL stores them, so a lock this attempt sets
		// reads back equal to the one it asked for.
		now: time.Now().UTC().Truncate(time.Microsecond),
	}
	if s.lockoutSource == nil {
		return a, nil
	}
	ctx, cancel := lockoutContext(ctx)
	defer cancel()
	tenantID, err := s.SignInTenant(ctx, in.ClientID)
	if err != nil {
		return a, lockoutFailed(stageSettings, err)
	}
	if a.lockout, err = s.lockoutSource(ctx, tenantID); err != nil {
		return a, lockoutFailed(stageSettings, err)
	}
	return a, nil
}

// SourceNetwork is the network a sign-in comes from: an IPv4 address, or the
// /64 an IPv6 address belongs to (one subscriber's allocation, so rotating
// addresses inside it is still one source). "" when ip is not an address.
func SourceNetwork(ip string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return ""
	}
	addr = addr.Unmap().WithZone("")
	if addr.Is4() {
		return addr.String()
	}
	prefix, err := addr.Prefix(64)
	if err != nil {
		return ""
	}
	return prefix.String()
}

func lockoutContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), lockoutStoreTimeout)
}

// lockoutFailed counts an evaluation that could not complete and refuses the
// sign-in (fail closed). The cause is kept for the request log.
func lockoutFailed(stage string, err error) error {
	lockoutUnavailable.WithLabelValues(stage).Inc()
	return errs.ErrAuthSignInUnavailable.Wrap(fmt.Errorf("sign-in lockout %s: %w", stage, err))
}

// checkLockout refuses an attempt from a throttled source network, or for an
// account locked for its network or everywhere — before the password is
// looked at, so a locked account answers the same whatever the password.
func (s *Service) checkLockout(ctx context.Context, a signInAttempt) error {
	ctx, cancel := lockoutContext(ctx)
	defer cancel()
	locks, err := s.q.GetSignInLocks(ctx, dbgen.GetSignInLocksParams{Email: a.email, Network: a.network, Now: a.now})
	if err != nil {
		return lockoutFailed(stageCheck, err)
	}
	if locks.SourceThrottledUntil.Valid {
		return errs.ErrTooManyRequests
	}
	if locks.NetworkLockedUntil.Valid || locks.AccountLockedUntil.Valid {
		return errs.ErrAuthAccountLocked
	}
	return nil
}

// recordFailedSignIn counts a failed attempt on all three counters in one
// transaction, then reports any lock or throttle it set — once, from the
// attempt that set it.
func (s *Service) recordFailedSignIn(ctx context.Context, a signInAttempt) error {
	ctx, cancel := lockoutContext(ctx)
	defer cancel()
	locks, throttle, err := s.countFailure(ctx, a)
	if err != nil {
		return lockoutFailed(stageRecord, err)
	}
	for _, lock := range locks {
		lockoutsSet.WithLabelValues(lock.Counter).Inc()
		slog.Warn("sign-in lockout: account locked",
			"counter", lock.Counter, "network", lock.Network, "failures", lock.Failures, "locked_until", lock.LockedUntil)
		if s.anomaly != nil {
			s.anomaly.OnAccountLocked(ctx, lock)
		}
	}
	if throttle != nil {
		sourceThrottles.Inc()
		slog.Warn("sign-in lockout: source network throttled for spraying",
			"network", throttle.Network, "distinct_accounts", len(throttle.Accounts), "throttled_until", throttle.ThrottledUntil)
		if s.anomaly != nil {
			s.anomaly.OnSourceThrottled(ctx, *throttle)
		}
	}
	return nil
}

func (s *Service) countFailure(ctx context.Context, a signInAttempt) ([]AccountLock, *SourceThrottle, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)

	lockUntil := a.now.Add(a.lockout.Duration)
	windowStart := a.now.Add(-a.lockout.Window)
	var locks []AccountLock
	network, err := q.RecordNetworkFailure(ctx, dbgen.RecordNetworkFailureParams{
		Email: a.email, Network: a.network, Now: a.now, WindowStart: windowStart,
		Threshold: int32(a.lockout.Threshold), LockUntil: lockUntil,
	})
	if err != nil {
		return nil, nil, err
	}
	if setNow(network.LockedUntil, lockUntil) {
		locks = append(locks, AccountLock{
			Email: a.email, Network: a.network, Counter: CounterAccountNetwork,
			Reason:   fmt.Sprintf("%d failed sign-ins from one network", network.FailedCount),
			Failures: int(network.FailedCount), Threshold: a.lockout.Threshold,
			Window: a.lockout.Window, LockedUntil: lockUntil,
		})
	}
	accountCap := a.lockout.Threshold * max(s.lockout.AccountMultiplier, 1)
	account, err := q.RecordAccountFailure(ctx, dbgen.RecordAccountFailureParams{
		Email: a.email, Now: a.now, WindowStart: windowStart,
		Threshold: int32(accountCap), LockUntil: lockUntil,
	})
	if err != nil {
		return nil, nil, err
	}
	if setNow(account.LockedUntil, lockUntil) {
		locks = append(locks, AccountLock{
			Email: a.email, Network: a.network, Counter: CounterAccount,
			Reason:   fmt.Sprintf("%d failed sign-ins from any network", account.FailedCount),
			Failures: int(account.FailedCount), Threshold: accountCap,
			Window: a.lockout.Window, LockedUntil: lockUntil,
		})
	}

	throttle, err := s.countSourceFailure(ctx, q, a)
	if err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	return locks, throttle, nil
}

// countSourceFailure adds the account to the accounts its source network
// failed against and throttles the network once they reach SourceAccounts.
// An attempt with no known network has no source to count.
func (s *Service) countSourceFailure(ctx context.Context, q *dbgen.Queries, a signInAttempt) (*SourceThrottle, error) {
	if a.network == "" || s.lockout.SourceAccounts <= 0 {
		return nil, nil
	}
	if err := q.RecordSourceFailure(ctx, dbgen.RecordSourceFailureParams{Network: a.network, Email: a.email, Now: a.now}); err != nil {
		return nil, err
	}
	if err := q.ForgetSourceFailuresBefore(ctx, dbgen.ForgetSourceFailuresBeforeParams{
		Network: a.network, WindowStart: a.now.Add(-s.lockout.SourceWindow),
	}); err != nil {
		return nil, err
	}
	accounts, err := q.CountSourceAccounts(ctx, a.network)
	if err != nil || accounts < int64(s.lockout.SourceAccounts) {
		return nil, err
	}
	until := a.now.Add(s.lockout.SourceBlock)
	if _, err := q.ThrottleSource(ctx, dbgen.ThrottleSourceParams{
		Network: a.network, Now: a.now, ThrottledUntil: until, DistinctAccounts: int32(accounts),
	}); errors.Is(err, pgx.ErrNoRows) {
		return nil, nil // another attempt throttled it first and reports it
	} else if err != nil {
		return nil, err
	}
	emails, err := q.TakeSourceAccounts(ctx, a.network)
	if err != nil {
		return nil, err
	}
	return &SourceThrottle{
		Network: a.network, Accounts: emails, Window: s.lockout.SourceWindow, ThrottledUntil: until,
		Reason: fmt.Sprintf("failed sign-ins against %d accounts from one network", len(emails)),
	}, nil
}

// setNow reports whether a counter's lock is the one this attempt asked for,
// i.e. this attempt set it (an older lock has an older expiry).
func setNow(lockedUntil pgtype.Timestamptz, asked time.Time) bool {
	return lockedUntil.Valid && lockedUntil.Time.Equal(asked)
}

// clearFailedSignIns forgets the account's failures after a successful
// sign-in: its count from this network and its account-wide count.
func (s *Service) clearFailedSignIns(ctx context.Context, a signInAttempt) error {
	ctx, cancel := lockoutContext(ctx)
	defer cancel()
	if err := s.q.ClearSignInFailures(ctx, dbgen.ClearSignInFailuresParams{Email: a.email, Network: a.network}); err != nil {
		return lockoutFailed(stageClear, err)
	}
	return nil
}

// timingHash is a password hash with the current parameters, verified when an
// address has no account (or no password) so that answer costs as long as a
// wrong password on a real account.
var timingHash = sync.OnceValue(func() string {
	h, err := password.Hash(uuid.NewString())
	if err != nil {
		return ""
	}
	return h
})

// verifyPassword checks plain against a stored hash. With no stored hash it
// still spends a full verification, so the outcome's timing does not reveal
// that the account has no password.
func verifyPassword(hash, plain string) bool {
	if hash == "" {
		password.Verify(timingHash(), plain)
		return false
	}
	return password.Verify(hash, plain)
}
