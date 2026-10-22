package errs

// Group error codes.
const (
	CodeGroupNotFound       = "group.not_found"
	CodeGroupNameExists     = "group.name_exists"
	CodeGroupUserNotFound   = "group.user_not_found"
	CodeGroupParentNotFound = "group.parent_not_found"
	CodeGroupCycle          = "group.cycle"

	// Reusable group-shape templates.
	CodeGroupTemplateUnnamed     = "group.template_unnamed"
	CodeGroupTemplateNodeUnnamed = "group.template_node_unnamed"
	CodeGroupTemplateEmpty       = "group.template_empty"
	CodeGroupTemplateTooDeep     = "group.template_too_deep"
	CodeGroupTemplateTooLarge    = "group.template_too_large"
	CodeGroupTemplateNameExists  = "group.template_name_exists"

	// Bulk import.
	CodeGroupImportEmpty    = "group.import_empty"
	CodeGroupImportTooLarge = "group.import_too_large"
)

// Group errors. ErrGroupUserNotFound and ErrGroupParentNotFound give the same
// answer for missing and other-organization IDs, so IDs can't be probed.
var (
	ErrGroupNotFound       = New(CodeGroupNotFound, "That group doesn't exist.")
	ErrGroupNameExists     = New(CodeGroupNameExists, "A group with that name already exists.")
	ErrGroupUserNotFound   = New(CodeGroupUserNotFound, "That user doesn't exist in this organization.")
	ErrGroupParentNotFound = New(CodeGroupParentNotFound, "That parent group doesn't exist in this organization.")
	ErrGroupCycle          = New(CodeGroupCycle, "A group can't be placed inside itself or one of its own subgroups.")

	ErrGroupTemplateUnnamed     = New(CodeGroupTemplateUnnamed, "Give the template a name.")
	ErrGroupTemplateNodeUnnamed = New(CodeGroupTemplateNodeUnnamed, "Every group in the template needs a name.")
	ErrGroupTemplateEmpty       = New(CodeGroupTemplateEmpty, "A template needs at least one group.")
	ErrGroupTemplateTooDeep     = New(CodeGroupTemplateTooDeep, "Templates can nest up to 6 levels deep.")
	ErrGroupTemplateTooLarge    = New(CodeGroupTemplateTooLarge, "A template can create at most 200 groups.")
	ErrGroupTemplateNameExists  = New(CodeGroupTemplateNameExists, "A template with that name already exists.")

	ErrGroupImportEmpty    = New(CodeGroupImportEmpty, "There are no groups to import.")
	ErrGroupImportTooLarge = New(CodeGroupImportTooLarge, "Import up to 500 groups at a time.")
)
