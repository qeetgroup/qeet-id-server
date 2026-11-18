package group

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// Codes callers compare an error with.
const (
	CodeNameExists = "group.name_exists"
)

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrNameExists          = errs.New(CodeNameExists, errs.KindConflict, "A group with that name already exists.")
	ErrCycle               = errs.New("group.cycle", errs.KindInvalid, "A group can't be placed inside itself or one of its own subgroups.")
	ErrTemplateUnnamed     = errs.New("group.template_unnamed", errs.KindUnprocessable, "Give the template a name.")
	ErrTemplateNodeUnnamed = errs.New("group.template_node_unnamed", errs.KindUnprocessable, "Every group in the template needs a name.")
	ErrTemplateEmpty       = errs.New("group.template_empty", errs.KindUnprocessable, "A template needs at least one group.")
	ErrTemplateTooDeep     = errs.New("group.template_too_deep", errs.KindUnprocessable, "Templates can nest up to 6 levels deep.")
	ErrTemplateTooLarge    = errs.New("group.template_too_large", errs.KindUnprocessable, "A template can create at most 200 groups.")
	ErrTemplateNameExists  = errs.New("group.template_name_exists", errs.KindConflict, "A template with that name already exists.")
	ErrImportEmpty         = errs.New("group.import_empty", errs.KindUnprocessable, "There are no groups to import.")
	ErrImportTooLarge      = errs.New("group.import_too_large", errs.KindUnprocessable, "Import up to 500 groups at a time.")
	// ErrUserNotFound and ErrParentNotFound give the same answer for missing and
	// other-organization IDs, so IDs can't be probed.
	ErrUserNotFound   = errs.New("group.user_not_found", errs.KindNotFound, "That user doesn't exist in this organization.")
	ErrParentNotFound = errs.New("group.parent_not_found", errs.KindNotFound, "That parent group doesn't exist in this organization.")
)
