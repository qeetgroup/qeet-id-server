package siem

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrSinkTypeInvalid = errs.New("siem.sink_type_invalid", errs.KindUnprocessable, "Choose a supported sink type: splunk_hec, datadog, or http.")
	ErrEndpointInvalid = errs.New("siem.endpoint_invalid", errs.KindUnprocessable, "Enter an absolute http(s) endpoint URL.")
	ErrIDInvalid       = errs.New("siem.id_invalid", errs.KindInvalid, "That reference is invalid.")
)
