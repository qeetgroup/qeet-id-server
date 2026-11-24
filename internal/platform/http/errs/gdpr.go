package errs

var (
	// ErrGDPRIDInvalid is a malformed reference in the path of a data-request
	// or compliance route; gdpr and compliance both answer it.
	ErrGDPRIDInvalid = New("gdpr.id_invalid", KindInvalid, "That reference is invalid.")
)
