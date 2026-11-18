package retention

import (
	"context"
	"errors"
	"fmt"

	"github.com/qeetgroup/qeet-id-server/internal/operations/retention/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
)

// Sweep is one platform-wide retention rule: a statement (in queries.sql)
// that deletes at most limit rows nothing needs any more from one table.
type Sweep struct {
	Name   string // what it deletes, as logged
	Delete func(q *dbgen.Queries, ctx context.Context, limit int32) (int64, error)
}

// SignInSweeps delete sign-in state once it is spent: links, codes, states and
// requests a day after they expire (kept that long so a late click is told the
// link expired rather than that it is unknown), and failed sign-in and wrong
// application secret counters a week after the last failure, once no lock or
// throttle is in force. A week is longer than any lockout window.
var SignInSweeps = []Sweep{
	{"authorization codes", (*dbgen.Queries).SweepAuthorizationCodes},
	{"consent requests", (*dbgen.Queries).SweepConsentRequests},
	{"device codes", (*dbgen.Queries).SweepDeviceCodes},
	{"backchannel requests", (*dbgen.Queries).SweepBackchannelRequests},
	{"sign-in links", (*dbgen.Queries).SweepSignInLinks},
	{"password resets", (*dbgen.Queries).SweepPasswordResets},
	{"email verifications", (*dbgen.Queries).SweepEmailVerifications},
	{"phone verifications", (*dbgen.Queries).SweepPhoneVerifications},
	{"SAML requests", (*dbgen.Queries).SweepSAMLRequests},
	{"federated sign-in codes", (*dbgen.Queries).SweepFederatedSignInCodes},
	{"federated sign-in states", (*dbgen.Queries).SweepFederatedSignInStates},
	{"platform social link codes", (*dbgen.Queries).SweepPlatformSocialLinkCodes},
	{"connected-account states", (*dbgen.Queries).SweepConnectedAccountStates},
	{"second-factor sign-ins", (*dbgen.Queries).SweepSecondFactorSignIns},
	{"failed sign-in counts", (*dbgen.Queries).SweepFailedSignInCounts},
	{"failed sign-in counts by network", (*dbgen.Queries).SweepFailedSignInCountsByNetwork},
	{"application secret failures", (*dbgen.Queries).SweepApplicationSecretFailures},
	{"failed sign-ins by source", (*dbgen.Queries).SweepFailedSignInsBySource},
	{"source throttles", (*dbgen.Queries).SweepSourceThrottles},
}

// RecordSweeps delete records once they stop being useful: finished webhook
// deliveries after 30 days (logout deliveries after a week), bot detections
// after 30 days, directory sync events and notifications after 90, security
// events and audit anomalies 90 days after they are resolved or a year after
// they were raised, invitations 90 days after they lapse, application grants a
// week after they end, and access decisions after 30 days. A delivery still to
// be made, an open alert and a live grant are kept. audit.events goes by each
// organization's plan instead (audit.PurgeExpired).
var RecordSweeps = []Sweep{
	{"webhook deliveries", (*dbgen.Queries).SweepWebhookDeliveries},
	{"logout deliveries", (*dbgen.Queries).SweepLogoutDeliveries},
	{"bot detections", (*dbgen.Queries).SweepBotDetections},
	{"security events", (*dbgen.Queries).SweepSecurityEvents},
	{"audit anomalies", (*dbgen.Queries).SweepAuditAnomalies},
	{"directory sync events", (*dbgen.Queries).SweepDirectorySyncEvents},
	{"notifications", (*dbgen.Queries).SweepNotifications},
	{"access decisions", (*dbgen.Queries).SweepAccessDecisions},
	// 13 months, so a year-on-year comparison and the last invoice's month remain.
	{"monthly active users", (*dbgen.Queries).SweepMonthlyActiveUsers},
	{"invitations", (*dbgen.Queries).SweepInvitations},
	// Oldest first, so a token goes no later than the one it was renewed from.
	{"application grants", (*dbgen.Queries).SweepApplicationGrants},
}

// RunSweeps runs each sweep in batches (postgres.DeleteInBatches) and returns
// how many rows each deleted. A failing sweep doesn't stop the rest; their
// errors are returned together.
func RunSweeps(ctx context.Context, db dbgen.DBTX, sweeps []Sweep) (map[string]int64, error) {
	q := dbgen.New(db)
	deleted := make(map[string]int64, len(sweeps))
	var errs []error
	for _, s := range sweeps {
		n, err := postgres.DeleteInBatches(ctx, func(ctx context.Context, limit int32) (int64, error) {
			return s.Delete(q, ctx, limit)
		})
		deleted[s.Name] = n
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.Name, err))
		}
	}
	return deleted, errors.Join(errs...)
}
