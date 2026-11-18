package ssosync

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// Codes callers compare an error with.
const (
	// Single sign-on group mappings.
	CodeGroupMappingPrivileged = "group.mapping_privileged"
	CodeGroupMappingExists     = "group.mapping_exists"
)

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrGroupMappingPrivileged = errs.New(CodeGroupMappingPrivileged, errs.KindUnprocessable, "Single sign-on can't manage this group's members: its roles carry the owner role or an administrative permission.")
	ErrGroupMappingExists     = errs.New(CodeGroupMappingExists, errs.KindConflict, "That identity provider group is already mapped to this group.")
	ErrGroupMappingTooMany    = errs.New("group.mapping_too_many", errs.KindUnprocessable, "A connection can map up to 1,000 identity provider groups.")
)
