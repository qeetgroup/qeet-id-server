package auth

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// refuseInactiveAccount refuses a sign-in for an account that is deleted, or
// neither active nor invited, with the answer password sign-in gives
// (ErrAuthAccountInactive), and audits the refusal as auth.sign_in_refused.
// It runs where every sign-in issues its session or hosted-login
// cookie, after the credential has been proved, so a path that proves it some
// other way — a passkey, a social provider, and any added later — can't skip
// it: suspending an account during an incident shuts every way back in, not
// only the password.
func (s *Service) refuseInactiveAccount(ctx context.Context, userID, tenantID uuid.UUID, method, ip, ua string) error {
	var status string
	var deleted bool
	err := s.pool.QueryRow(ctx, `SELECT status, deleted_at IS NOT NULL FROM "user".users WHERE id = $1`, userID).
		Scan(&status, &deleted)
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrAuthAccountInactive
	}
	if err != nil {
		return err
	}
	if !deleted && (status == "active" || status == "invited") {
		return nil
	}
	var tenantPtr *uuid.UUID
	if tenantID != uuid.Nil {
		tenantPtr = &tenantID
	}
	_ = s.auditTx(ctx, audit.Event{TenantID: tenantPtr, ActorUserID: &userID, ActorType: "user",
		Action: "auth.sign_in_refused", ResourceType: "user", ResourceID: &userID, IP: ip, UserAgent: ua,
		Metadata: map[string]any{"reason": "account_inactive", "status": status, "deleted": deleted, "method": method}})
	return errs.ErrAuthAccountInactive
}

// CheckSignInAccount is refuseInactiveAccount for a sign-in that hands out
// something before the session — a social provider's one-time code, which
// would otherwise be issued to a suspended account and refused only at the
// exchange.
func (s *Service) CheckSignInAccount(ctx context.Context, userID, tenantID uuid.UUID, method, ip, ua string) error {
	return s.refuseInactiveAccount(ctx, userID, tenantID, method, ip, ua)
}
