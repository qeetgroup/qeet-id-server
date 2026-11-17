package auth

// Sign-in lockout counts failed password sign-ins in PostgreSQL, so all replicas
// agree: per account and network, per account across networks, and per network
// across accounts (spraying). Unknown addresses count like real ones. If the
// counters are unavailable, sign-in fails closed with ErrAuthSignInUnavailable.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
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

// noLooserThan is l held at least as strict as base: the lower threshold and
// the longer window and lock win. It governs the lock on one network; the lock
// on every network always uses the platform's settings.
func (l Lockout) noLooserThan(base Lockout) Lockout {
	return Lockout{Threshold: min(l.Threshold, base.Threshold), Window: max(l.Window, base.Window), Duration: max(l.Duration, base.Duration)}
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
// LOGIN_LOCKOUT_* and LOGIN_SPRAY_*).
func (s *Service) SetLockoutConfig(c LockoutConfig) { s.lockout = c }

// SetLockoutSource wires the per-tenant lockout settings.
func (s *Service) SetLockoutSource(f LockoutSource) { s.lockoutSource = f }

// AccountLock describes a lock at the moment it is set, for security monitoring.
type AccountLock struct {
	Email       string        // the account's lowercased address
	Network     string        // the source network that set the lock ("" if unknown)
	Counter     string        // CounterAccountNetwork or CounterAccount
	Reason      string        // human-readable cause, such as "5 failed sign-ins from one network"
	Failures    int           // failures counted
	Threshold   int           // failures that set the lock
	Window      time.Duration // how long a failure is remembered
	LockedUntil time.Time     // when the lock lifts
}

// SourceThrottle describes a source network at the moment it is throttled.
type SourceThrottle struct {
	Network        string        // the throttled source network
	Accounts       []string      // distinct accounts it failed against within Window
	Window         time.Duration // the counting window
	ThrottledUntil time.Time     // when the throttle lifts
	Reason         string        // human-readable cause
}

// signInAttempt is one password sign-in as the lockout sees it.
type signInAttempt struct {
	email   string
	network string
	lockout Lockout
	now     time.Time
}

// SignInTenant returns the tenant whose authentication policy governs a sign-in
// before the credential is verified: the hosted login's OAuth client's tenant,
// or uuid.Nil for the platform defaults. It never uses the account's own tenant,
// which would reveal whether the address has an account.
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
	if s.lockoutSource == nil {
		return s.signInAttemptIn(ctx, uuid.Nil, in.Email, in.IP)
	}
	lctx, cancel := lockoutContext(ctx)
	defer cancel()
	tenantID, err := s.SignInTenant(lctx, in.ClientID)
	if err != nil {
		return signInAttempt{}, lockoutFailed(stageSettings, err)
	}
	return s.signInAttemptIn(ctx, tenantID, in.Email, in.IP)
}

// signInAttemptIn is an attempt to sign in as account from ip, held to
// tenantID's lockout (uuid.Nil: the platform defaults). A sign-in may name any
// organisation's application, so its lockout can tighten the platform's but
// never loosen it for someone else's account.
func (s *Service) signInAttemptIn(ctx context.Context, tenantID uuid.UUID, account, ip string) (signInAttempt, error) {
	a := signInAttempt{
		network: httpx.SourceNetwork(ip),
		lockout: s.lockout.Defaults,
		// Microseconds, as PostgreSQL stores them, so a lock this attempt sets
		// reads back equal to the one it asked for.
		now: time.Now().UTC().Truncate(time.Microsecond),
	}
	ctx, cancel := lockoutContext(ctx)
	defer cancel()
	// The address is folded by the database's LOWER, as the account lookup
	// folds it, so a case variant never gets a counter of its own.
	if err := s.pool.QueryRow(ctx, `SELECT LOWER($1::text)`, strings.TrimSpace(account)).Scan(&a.email); err != nil {
		return a, lockoutFailed(stageSettings, err)
	}
	if s.lockoutSource == nil {
		return a, nil
	}
	var err error
	if a.lockout, err = s.lockoutSource(ctx, tenantID); err != nil {
		return a, lockoutFailed(stageSettings, err)
	}
	a.lockout = a.lockout.noLooserThan(s.lockout.Defaults)
	return a, nil
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

// refuseLocked is checkLockout that also records a refused attempt as a failed
// sign-in. owner, when not nil, names the account for the record.
func (s *Service) refuseLocked(ctx context.Context, a signInAttempt, f SignInFailure, owner func() uuid.UUID) error {
	err := s.checkLockout(ctx, a)
	if errors.Is(err, errs.ErrAuthAccountLocked) || errors.Is(err, errs.ErrTooManyRequests) {
		f.Reason = FailureAccountLocked
		if errors.Is(err, errs.ErrTooManyRequests) {
			f.Reason = FailureSourceThrottled
		}
		if owner != nil {
			f.UserID = owner()
		}
		s.RecordSignInFailure(ctx, f)
	}
	return err
}

// recordFailedSignIn counts a failed attempt on all three counters in one
// transaction, then reports any lock or throttle it set — once, from the
// attempt that set it — and records the failure and what it set in the audit
// trail (signinaudit.go).
func (s *Service) recordFailedSignIn(ctx context.Context, a signInAttempt, f SignInFailure) error {
	ctx, cancel := lockoutContext(ctx)
	defer cancel()
	locks, throttle, err := s.countFailure(ctx, a)
	if err != nil {
		return lockoutFailed(stageRecord, err)
	}
	s.RecordSignInFailure(ctx, f)
	s.recordLocks(ctx, f, locks, throttle)
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
		Threshold: int32(a.lockout.Threshold), LockUntil: lockUntil, // #nosec G115 -- bounded by the lockout limits
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
	// The lock on every network is the platform's alone: an organisation's
	// stricter settings would let its application lock anyone out everywhere.
	platform := s.lockout.Defaults
	accountCap := platform.Threshold * max(s.lockout.AccountMultiplier, 1)
	accountUntil := a.now.Add(platform.Duration)
	account, err := q.RecordAccountFailure(ctx, dbgen.RecordAccountFailureParams{
		Email: a.email, Now: a.now, WindowStart: a.now.Add(-platform.Window),
		Threshold: int32(accountCap), LockUntil: accountUntil, // #nosec G115 -- bounded threshold × small multiplier
	})
	if err != nil {
		return nil, nil, err
	}
	if setNow(account.LockedUntil, accountUntil) {
		locks = append(locks, AccountLock{
			Email: a.email, Network: a.network, Counter: CounterAccount,
			Reason:   fmt.Sprintf("%d failed sign-ins from any network", account.FailedCount),
			Failures: int(account.FailedCount), Threshold: accountCap,
			Window: platform.Window, LockedUntil: accountUntil,
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
		Network: a.network, Now: a.now, ThrottledUntil: until, DistinctAccounts: int32(accounts), // #nosec G115 -- account count, far below 2^31
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

// timing holds a password hash with the current parameters, verified when an
// address has no account (or no password) so that answer costs as long as a
// wrong password on a real account.
var timing atomic.Pointer[string]

// timingHash returns timing's hash, made on first use. A hasher too busy to
// make it now returns ErrHasherBusy, and a later call tries again.
func timingHash() (string, error) {
	if h := timing.Load(); h != nil {
		return *h, nil
	}
	h, err := password.Hash(uuid.NewString())
	if err != nil {
		return "", err
	}
	timing.CompareAndSwap(nil, &h)
	return *timing.Load(), nil
}

// verifyPassword checks plain against a stored hash. With no stored hash it
// still spends a full verification, so the outcome's timing does not reveal
// that the account has no password. When the hasher is too busy it returns
// errs.ErrServerOverloaded, which is not a failed sign-in.
func verifyPassword(ctx context.Context, hash, plain string) (bool, error) {
	stored := hash
	if stored == "" {
		var err error
		if stored, err = timingHash(); err != nil {
			return false, err
		}
	}
	ok, err := password.VerifyWithin(ctx, stored, plain)
	return ok && hash != "" && err == nil, err
}
