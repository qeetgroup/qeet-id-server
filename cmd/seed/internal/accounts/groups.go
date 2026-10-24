package accounts

import (
	"time"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	group "github.com/qeetgroup/qeet-id-server/internal/identity/groups"
)

// groupRoles are roles granted to a whole team: everyone in the group holds
// the role's permissions on top of their own. None widens a test account's
// console beyond what its summary line promises.
var groupRoles = map[string][][2]string{
	"qeet":      {{"Governance, Risk & Compliance", world.RoleAuditor}},
	"northwind": {{"IT Operations", world.RoleITAdmin}, {"Internal Audit", world.RoleAuditor}},
	"meridian":  {{"Service Desk", world.RoleHelpdesk}, {"HIPAA Privacy", world.RoleAuditor}},
	"vertex":    {{"IT Support", world.RoleITAdmin}},
}

// groupTemplates are the group trees organisations saved to stamp out again.
var groupTemplates = map[string][]group.TemplateInput{
	"qeet": {{
		Name: "Product squad", Description: "A cross-functional squad: engineers, design and product",
		Nodes: []group.TemplateNode{{Name: "Squad", Description: "Everyone in the squad", Children: []group.TemplateNode{
			{Name: "Squad Engineering", Description: "Backend and frontend engineers"},
			{Name: "Squad Design", Description: "Product and UX design"},
			{Name: "Squad Product", Description: "Product manager and analyst"},
		}}},
	}},
	"northwind": {
		{
			Name: "Branch office", Description: "Groups for a new lending branch",
			Nodes: []group.TemplateNode{{Name: "Branch", Description: "Everyone at the branch", Children: []group.TemplateNode{
				{Name: "Branch Operations", Description: "Disbursement and customer service"},
				{Name: "Branch Credit", Description: "Credit underwriting"},
				{Name: "Branch Collections", Description: "Collections officers"},
			}}},
		},
		{
			Name: "Audit engagement", Description: "Time-boxed access for an external audit",
			Nodes: []group.TemplateNode{{Name: "Audit engagement", Description: "External auditors on an engagement", Children: []group.TemplateNode{
				{Name: "Audit engagement — fieldwork", Description: "Read-only access during fieldwork"},
			}}},
		},
	},
	"meridian": {{
		Name: "Hospital unit", Description: "Groups for a new clinical unit",
		Nodes: []group.TemplateNode{{Name: "Unit", Description: "Everyone on the unit", Children: []group.TemplateNode{
			{Name: "Unit Nursing", Description: "Registered and charge nurses"},
			{Name: "Unit Physicians", Description: "Attending physicians"},
			{Name: "Unit Clerks", Description: "Unit secretaries and patient access"},
		}}},
	}},
}

// groups grants roles to teams and saves group templates, a few weeks into
// each organisation's life.
func (s *seeder) groups(o *world.Org) {
	w := s.w
	for i, gr := range groupRoles[o.Spec.Slug] {
		gid, ok := o.Groups[gr[0]]
		rid, has := o.Roles[gr[1]]
		if !ok || !has {
			continue
		}
		at := clamp(w, w.WorkHours(o.Spec.Since.Add(time.Duration(5+9*i)*24*time.Hour), o.Loc))
		actor := by(o, at)
		w.At(at, func() {
			w.Check(w.Deps.RBAC.Service.AssignRoleToGroup(w.Ctx, gid, o.ID, rid, &actor.ID, actor.Actor()), "group role "+gr[0])
		})
	}
	for i, t := range groupTemplates[o.Spec.Slug] {
		at := clamp(w, w.WorkHours(o.Spec.Since.Add(time.Duration(30+40*i)*24*time.Hour), o.Loc))
		actor := by(o, at)
		w.At(at, func() {
			_, err := w.Deps.Group.Service.CreateTemplate(w.Ctx, o.ID, t, actor.Actor())
			w.Check(err, "group template "+t.Name)
		})
	}
}
