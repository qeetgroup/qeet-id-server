package mfa

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
)

// PushDevice is a phone paired to approve sign-ins by push.
type PushDevice struct {
	ID         uuid.UUID `json:"id"`
	Name       string    `json:"name"`
	Platform   string    `json:"platform"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
}

// PushChallenge is a sign-in or step-up waiting for approval on a paired
// phone.
type PushChallenge struct {
	ID        uuid.UUID       `json:"id"`
	UserID    uuid.UUID       `json:"user_id"`
	Action    string          `json:"action"`
	Context   json.RawMessage `json:"context"`
	Status    string          `json:"status"`
	ExpiresAt time.Time       `json:"expires_at"`
	CreatedAt time.Time       `json:"created_at"`
}

// PushChallengeContext is shown in the app so the user can decide whether to
// approve. SessionID is the session a step-up request was raised for; only
// that session is stepped up when it is approved.
type PushChallengeContext struct {
	IP        string `json:"ip,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Location  string `json:"location,omitempty"`
	Timestamp string `json:"timestamp"`
	SessionID string `json:"session_id,omitempty"`
}

// loadPushTokens opens the push tokens of the person's linked phones whose
// device credential hasn't expired.
func (s *Service) loadPushTokens(ctx context.Context, tx pgx.Tx, userID uuid.UUID) ([]pushTarget, error) {
	rows, err := s.q.WithTx(tx).ListPushTargets(ctx, userID)
	if err != nil {
		return nil, err
	}
	var tokens []pushTarget
	for _, row := range rows {
		if s.box == nil {
			return nil, errors.New("MFA secret encryption is unavailable")
		}
		plain, err := s.box.Open(userID, "mfa-push-token", row.PushTokenHash, row.PushTokenCt, row.PushTokenNonce)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, pushTarget{token: string(plain), platform: row.Platform})
	}
	return tokens, nil
}

// secretHash is the stored form of a push token, device token or pairing code.
func secretHash(secret string) string { return codes.HashHex(secret) }

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
