package errs

// Group error codes.
const (
	CodeGroupNotFound = "group.not_found"
)

// Group errors. ErrGroupUserNotFound and ErrGroupParentNotFound give the same
// answer for missing and other-organization IDs, so IDs can't be probed.
var (
	ErrGroupNotFound       = New(CodeGroupNotFound, KindNotFound, "That group doesn't exist.")
	ErrGroupUserNotFound   = New("group.user_not_found", KindNotFound, "That user doesn't exist in this organization.")
	ErrGroupParentNotFound = New("group.parent_not_found", KindNotFound, "That parent group doesn't exist in this organization.")
)
