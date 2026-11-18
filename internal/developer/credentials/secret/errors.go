package secret

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrNameValueRequired          = errs.New("secret.name_value_required", errs.KindUnprocessable, "A secret name and value are required.")
	ErrNameExists                 = errs.New("secret.name_exists", errs.KindConflict, "A secret with that name already exists.")
	ErrValueRequired              = errs.New("secret.value_required", errs.KindUnprocessable, "A secret value is required.")
	ErrDecryptFailed              = errs.New("secret.decrypt_failed", errs.KindInternal, "We couldn't decrypt this secret.")
	ErrScopeRequired              = errs.New("secret.scope_required", errs.KindForbidden, "You don't have permission to access this secret.")
	ErrRotationIntervalOutOfRange = errs.New("secret.rotation_interval_out_of_range", errs.KindUnprocessable, "A rotation interval is between 1 and 3650 days.")
	ErrNotFound                   = errs.New("secret.not_found", errs.KindNotFound, "We couldn't find that secret.")
)
