package errs

// Group error codes — stable, namespaced machine identifiers for the
// internal/identity/groups domain. Clients branch and localize on these (never
// on the message text). Once shipped, a code MUST NOT change. Every identifier
// is prefixed with the `group` domain so it never collides with another
// bounded context.
const (
	CodeGroupNotFound     = "group.not_found"
	CodeGroupNameExists   = "group.name_exists"
	CodeGroupUserNotFound = "group.user_not_found"

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

// Group errors. The Message is what the end user sees — edit wording here, in
// one place. Handlers just `return errs.ErrGroupNotFound`.
var (
	ErrGroupNotFound   = New(CodeGroupNotFound, "That group doesn't exist.")
	ErrGroupNameExists = New(CodeGroupNameExists, "A group with that name already exists.")
	// ErrGroupUserNotFound is the one answer to adding anyone who isn't a live
	// member of the organization, whether the id is missing or belongs to
	// another organization, so the response can't be used to probe for ids.
	ErrGroupUserNotFound = New(CodeGroupUserNotFound, "That user doesn't exist in this organization.")

	ErrGroupTemplateUnnamed     = New(CodeGroupTemplateUnnamed, "Give the template a name.")
	ErrGroupTemplateNodeUnnamed = New(CodeGroupTemplateNodeUnnamed, "Every group in the template needs a name.")
	ErrGroupTemplateEmpty       = New(CodeGroupTemplateEmpty, "A template needs at least one group.")
	ErrGroupTemplateTooDeep     = New(CodeGroupTemplateTooDeep, "Templates can nest up to 6 levels deep.")
	ErrGroupTemplateTooLarge    = New(CodeGroupTemplateTooLarge, "A template can create at most 200 groups.")
	ErrGroupTemplateNameExists  = New(CodeGroupTemplateNameExists, "A template with that name already exists.")

	ErrGroupImportEmpty    = New(CodeGroupImportEmpty, "There are no groups to import.")
	ErrGroupImportTooLarge = New(CodeGroupImportTooLarge, "Import up to 500 groups at a time.")
)
