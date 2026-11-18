package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// A refresh token sent again soon after its rotation, by a client that renewed
// twice at once or lost the answer, gets the pair the rotation issued rather
// than ending the session. Only within the grace and while that pair's refresh
// token is unused: any other reuse still ends the session as theft.

// refreshRetryPurpose is the encryption context of a kept rotation pair.
const refreshRetryPurpose = "refresh-token-retry"

// refreshRetryOn reports whether each rotation keeps the pair it issued, so
// the rotated token sent again within the grace gets that pair.
func (s *Service) refreshRetryOn() bool { return s.refreshGrace > 0 }

// keepRotation stores pair, sealed, on rotated, the refresh token it replaces.
// The session ID is the context, as an organization-less session has no organization.
func (s *Service) keepRotation(ctx context.Context, tx pgx.Tx, rotated uuid.UUID, pair *TokenPair) error {
	if !s.refreshRetryOn() {
		return nil
	}
	plain, err := json.Marshal(pair) // #nosec G117 -- sealed below; never stored or logged in clear
	if err != nil {
		return err
	}
	enc, nonce, err := s.refreshCipher.Seal(pair.SessionID, refreshRetryPurpose, rotated.String(), plain)
	if err != nil {
		return err
	}
	return s.q.WithTx(tx).KeepRotation(ctx, dbgen.KeepRotationParams{ID: rotated, ReplacementEnc: enc, ReplacementNonce: nonce})
}

// keptRotation returns the pair issued by the rotation of the used token, and how long ago, when that
// was within the grace and its refresh token is unused and live; otherwise ok is false (also when the
// pair can't be opened), so the reuse counts as theft. The caller holds the session's row lock, which
// every renewal takes, so the replacement can't be used meanwhile.
func (s *Service) keptRotation(ctx context.Context, tx pgx.Tx, rotated, sessionID uuid.UUID) (pair *TokenPair, age time.Duration, ok bool, err error) {
	if !s.refreshRetryOn() {
		return nil, 0, false, nil
	}
	kept, err := s.q.WithTx(tx).KeptRotation(ctx, dbgen.KeptRotationParams{ID: rotated, SessionID: sessionID, GraceS: s.refreshGrace.Seconds()})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, 0, false, nil
	}
	if err != nil {
		return nil, 0, false, err
	}
	nextHash, seconds := kept.TokenHash, kept.Seconds
	plain, err := s.refreshCipher.Open(sessionID, refreshRetryPurpose, rotated.String(), kept.ReplacementEnc, kept.ReplacementNonce)
	if err != nil {
		slog.Warn("auth: kept refresh rotation could not be opened", "refresh_token_id", rotated, "err", err)
		return nil, 0, false, nil
	}
	pair = &TokenPair{}
	if err := json.Unmarshal(plain, pair); err != nil || tokens.HashRefresh(pair.RefreshToken) != nextHash {
		slog.Warn("auth: kept refresh rotation does not match its replacement", "refresh_token_id", rotated)
		return nil, 0, false, nil //nolint:nilerr // a pair that doesn't match is no retry: the reuse counts as theft
	}
	return pair, time.Duration(math.Max(seconds, 0) * float64(time.Second)), true, nil
}

// answerRetry answers a rotated token sent again within the grace with the
// pair its rotation issued, once the address rules allow the renewal, and
// audits it as auth.refresh_token_retried.
func (s *Service) answerRetry(ctx context.Context, tx pgx.Tx, pair *TokenPair, age time.Duration, rotated uuid.UUID,
	userID, organizationID uuid.UUID, in RefreshInput) (*TokenPair, error) {
	if err := s.checkAddressTx(ctx, tx, organizationID, userID, in.IP, "refresh"); err != nil {
		if errors.Is(err, errs.ErrAuthAddressNotAllowed) {
			if cerr := tx.Commit(ctx); cerr != nil {
				return nil, cerr
			}
		}
		return nil, err
	}
	if err := audit.Record(ctx, tx, as(in.Actor, "user", &userID).EventIn(pair.OrganizationID, "auth.refresh_token_retried", "session", pair.SessionID,
		map[string]any{"refresh_token_id": rotated, "seconds_since_rotation": int(age.Round(time.Second).Seconds())})); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return pair, nil
}

// refreshRetryKept is how long a rotation's sealed pair is kept: past the
// longest grace, so a retry within it still finds the pair.
const refreshRetryKept = 2 * time.Minute

// ClearRefreshRetries removes the sealed pairs of rotations older than any
// grace and returns how many. Run on a schedule.
func ClearRefreshRetries(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	return dbgen.New(pool).ClearRefreshRetries(ctx, new(time.Now().UTC().Add(-refreshRetryKept)))
}
