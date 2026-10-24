package accounts

import (
	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
)

// summary adds the identity step's notes: invitation links to accept in the
// console, and where to find the settings and account states it seeded.
func (s *seeder) summary() {
	w := s.w
	for _, l := range s.links {
		w.Note("Invitations — open the link signed out; the console's accept page creates the account", "%s", l)
	}
	const section = "Organisation settings and account states"
	suspended, pending, deleted := 0, 0, 0
	for _, o := range w.Orgs {
		for _, p := range o.People {
			switch p.Status {
			case world.StatusSuspended:
				suspended++
				if !p.Since.Before(w.Days(10)) || risks[p.Reason] == "high" {
					pending++
				}
			case world.StatusDeleted:
				deleted++
			}
		}
	}
	w.Note(section, "Northwind Capital: MFA required, 14-character passwords, 12h sessions / 30m idle, lockout after 3 failures;")
	w.Note(section, "  login domain login.northwindcapital.in and Meridian's sso.meridianhealth.us show DNS pending (Settings → Domains)")
	w.Note(section, "Domains: verified, pending (Vertex, Meridian, Aster) and needing attention (Northwind nwcfinance.in, Lumen)")
	w.Note(section, "Lumen Labs: hosted self-registration on, 15-minute magic links, German invite and magic-link emails")
	w.Note(section, "Kestrel: MFA required with a 14-day grace; Meridian: MFA for administrators with a 7-day grace")
	w.Note(section, "%d suspended accounts (%d awaiting review) and %d deleted; erasure requests pending, completed and cancelled", suspended, pending, deleted)
}
