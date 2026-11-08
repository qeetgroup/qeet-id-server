package errs

// Access request error codes.
const (
	CodeAccessRequestRoleHeld   = "access_request.role_held"
	CodeAccessRequestPending    = "access_request.pending"
	CodeAccessRequestClosed     = "access_request.closed"
	CodeAccessRequestOwn        = "access_request.own"
	CodeAccessRequestNoteNeeded = "access_request.note_required"
)

var (
	ErrAccessRequestRoleHeld   = New(CodeAccessRequestRoleHeld, "You already have this role.")
	ErrAccessRequestPending    = New(CodeAccessRequestPending, "You've already asked for this role. Wait for an answer, or cancel that request.")
	ErrAccessRequestClosed     = New(CodeAccessRequestClosed, "This request has already been answered, cancelled or has expired.")
	ErrAccessRequestOwn        = New(CodeAccessRequestOwn, "Someone else has to answer your own request.")
	ErrAccessRequestNoteNeeded = New(CodeAccessRequestNoteNeeded, "Say why you're denying it. They'll see your reason.")
)
