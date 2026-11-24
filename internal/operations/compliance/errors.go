package compliance

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message, so these keep the gdpr
// codes they were first shipped with.
var (
	ErrFrameworkInvalid = errs.New("gdpr.framework_invalid", errs.KindInvalid, "Choose a supported framework: soc2 or iso27001.")
	ErrIDInvalid        = errs.ErrGDPRIDInvalid
)
