package accounts

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/operations/gdpr"
)

// grace is how long an erasure request waits before the purge, as the API is
// configured (gdpr.NewService in bootstrap).
const grace = 30 * 24 * time.Hour

// erasureReason is why an organisation files an erasure request, in its
// jurisdiction's terms.
func erasureReason(o *world.Org) string {
	switch o.Spec.Country {
	case "IN":
		return "Former employee: erasure under the Digital Personal Data Protection Act 2023, s.12"
	case "US":
		return "Offboarded workforce member: erase per the records retention schedule"
	default:
		return "Former employee: erasure request under GDPR Art. 17"
	}
}

// erasures files an erasure request for each leaver a few hours after the
// account was deleted. Requests whose 30-day grace has run out were carried
// out — the account redacted as the API's purge does — and the rest are
// still pending, ending at least a day from now so the API's sweeper leaves
// them for testers. One request filed for a suspended account under
// investigation was cancelled.
func (s *seeder) erasures(o *world.Org) {
	w := s.w
	svc := w.Deps.GDPR.Service
	for _, p := range o.People {
		if p.Status != world.StatusDeleted {
			continue
		}
		filed := clamp(w, w.WorkHours(p.Since.Add(time.Duration(2+w.Rand.IntN(20))*time.Hour), o.Loc))
		if filed.Before(p.Since) {
			filed = p.Since.Add(2 * time.Hour)
		}
		ends := filed.Add(grace)
		if ends.After(w.Now.Add(-time.Hour)) && ends.Before(w.Now.Add(24*time.Hour)) {
			filed = w.Now.Add(36*time.Hour - grace)
			ends = filed.Add(grace)
		}
		requester := by(o, filed, world.RoleAdmin)
		var req *gdpr.Request
		w.At(filed, func() {
			var err error
			req, err = svc.Request(w.Ctx, gdpr.CreateInput{TenantID: o.ID, UserID: p.ID, Reason: erasureReason(o)}, requester.Actor())
			w.Check(err, "erasure request for "+p.Email)
		})
		// The service set the grace period's end from the clock, which At
		// doesn't move.
		w.Exec("grace of erasure request", `UPDATE "user".purge_requests SET grace_until = $3 WHERE id = $1 AND tenant_id = $2`,
			req.ID, o.ID, ends)
		if ends.Before(w.Now) {
			s.purged(o, p, req.ID, ends.Add(time.Duration(1+w.Rand.IntN(50))*time.Second))
			s.tell(o, event{at: ends.Add(2 * time.Minute), kind: "success", title: "Personal data erased",
				detail: "The erasure request for a former member was carried out after its 30-day grace period.",
				href:   "/security/compliance/gdpr"})
			continue
		}
		s.tell(o, event{at: filed.Add(time.Minute), kind: "info", title: "Erasure scheduled: " + p.Name(),
			detail: fmt.Sprintf("%s's personal data will be erased on %s. Cancel the request before then to keep it.",
				p.Name(), ends.In(o.Loc).Format("2 Jan 2006")),
			href: "/security/compliance/gdpr"})
	}

	// A request filed against a suspended account, then withdrawn: the
	// account is under investigation and on legal hold.
	for _, p := range o.People {
		if p.Status != world.StatusSuspended || (p.Reason != "suspicious_activity" && p.Reason != "policy_violation") {
			continue
		}
		filed := p.Since.Add(3 * 24 * time.Hour)
		if filed.After(w.Days(1)) {
			continue
		}
		requester := by(o, filed, world.RoleAdmin)
		var cancelled uuid.UUID
		w.At(filed, func() {
			req, err := svc.Request(w.Ctx, gdpr.CreateInput{TenantID: o.ID, UserID: p.ID,
				Reason: erasureReason(o) + " (filed in error: account on legal hold)"}, requester.Actor())
			w.Check(err, "erasure request for "+p.Email)
			w.Check(svc.Cancel(w.Ctx, o.ID, req.ID, requester.Actor()), "cancel erasure request for "+p.Email)
			cancelled = req.ID
		})
		w.Exec("grace of erasure request", `UPDATE "user".purge_requests SET grace_until = $3 WHERE id = $1 AND tenant_id = $2`,
			cancelled, o.ID, filed.Add(grace))
		break
	}
}

// purged marks request id completed at done and erases p's account at done
// with the API's own erasure: personal data redacted, everything else the
// account left deleted. The census's record of p's factors is cleared so later
// steps don't give the erased account new ones.
func (s *seeder) purged(o *world.Org, p *world.Person, id uuid.UUID, done time.Time) {
	w := s.w
	w.Exec("complete erasure", `UPDATE "user".purge_requests SET status = 'completed', completed_at = $3
		WHERE id = $1 AND tenant_id = $2`, id, o.ID, done)
	w.At(done, func() {
		w.Check(w.Deps.GDPR.Service.PurgeSelf(w.Ctx, p.ID), "erase "+p.Email)
	})
	p.MFA, p.MFASince = nil, time.Time{}
}

// exports writes data-export requests: two that were built and downloaded
// (one for a leaver before their account went, one for an account under
// investigation) and one just filed, which the API's sweeper builds when it
// next runs.
func (s *seeder) exports(o *world.Org) {
	w := s.w
	var subject *world.Person
	var at time.Time
	switch o.Spec.Slug {
	case "lumen":
		for _, p := range o.People {
			if p.Status == world.StatusDeleted {
				subject, at = p, p.Since.Add(-2*24*time.Hour)
				break
			}
		}
	case "northwind":
		for _, p := range o.People {
			if p.Status == world.StatusSuspended && p.Reason == "suspicious_activity" {
				subject, at = p, p.Since.Add(26*time.Hour)
				break
			}
		}
	case "qeet":
		for _, p := range o.Active() {
			if p.Department == "Operations" && p.Login == "" && p.Manager != o.Owner {
				subject, at = p, w.Now.Add(-25*time.Minute)
				break
			}
		}
	}
	if subject == nil || at.After(w.Now) {
		return
	}
	at = clamp(w, at)
	requester := by(o, at, world.RoleAdmin)
	var req *gdpr.ExportRequest
	w.At(at, func() {
		var err error
		req, err = w.Deps.GDPR.Service.RequestExport(w.Ctx, gdpr.ExportInput{TenantID: o.ID, UserID: subject.ID}, requester.Actor())
		w.Check(err, "export request for "+subject.Email)
	})
	if o.Spec.Slug == "qeet" {
		return
	}
	done := at.Add(time.Duration(40+w.Rand.IntN(80)) * time.Second)
	payload, err := w.Deps.GDPR.Service.ExportSelf(w.Ctx, subject.ID)
	w.Check(err, "export of "+subject.Email)
	payload["generated_at"] = done
	raw, err := json.Marshal(payload)
	w.Check(err, "encode export of "+subject.Email)
	w.Exec("export ready", `UPDATE "user".export_requests SET status = 'ready', payload = $3, completed_at = $4
		WHERE id = $1 AND tenant_id = $2`, req.ID, o.ID, raw, done)
	// The API deletes a payload once it has been downloadable for the retention window.
	if done.Before(w.Now.Add(-gdpr.ExportRetention)) {
		w.Exec("export expired", `UPDATE "user".export_requests SET status = 'expired', payload = NULL
			WHERE id = $1 AND tenant_id = $2`, req.ID, o.ID)
	}
}
