package scim

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// userRow is the SCIM read side (includes external_id, which user.User omits).
type userRow struct {
	ID          uuid.UUID
	Email       string
	DisplayName *string
	Status      string
	ExternalID  *string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (s *Service) getProvisioned(ctx context.Context, organizationID, id uuid.UUID) (*userRow, error) {
	r, err := s.q.GetProvisionedUser(ctx, dbgen.GetProvisionedUserParams{
		ID:             id,
		OrganizationID: &organizationID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &userRow{
		ID:          r.ID,
		Email:       r.Email,
		DisplayName: r.DisplayName,
		Status:      r.Status,
		ExternalID:  r.ExternalID,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}, nil
}

// listProvisioned lists the organization's directory-provisioned users. A
// userName lookup finds any account at home there, whoever created it, so an
// identity provider can match and link the people who are already members.
func (s *Service) listProvisioned(ctx context.Context, organizationID uuid.UUID, emailFilter string, start, count int) ([]userRow, int, error) {
	lim, off := int64(count), int64(start-1) // SCIM startIndex is 1-based
	var total int64
	var rows []dbgen.ListProvisionedUsersRow
	var err error
	if emailFilter != "" {
		if total, err = s.q.CountHomeUsersByEmail(ctx, dbgen.CountHomeUsersByEmailParams{OrganizationID: &organizationID, Email: emailFilter}); err != nil {
			return nil, 0, err
		}
		var found []dbgen.ListHomeUsersByEmailRow
		found, err = s.q.ListHomeUsersByEmail(ctx, dbgen.ListHomeUsersByEmailParams{OrganizationID: &organizationID, Email: emailFilter, Lim: lim, Off: off})
		for _, r := range found {
			rows = append(rows, dbgen.ListProvisionedUsersRow(r))
		}
	} else {
		if total, err = s.q.CountProvisionedUsers(ctx, &organizationID); err != nil {
			return nil, 0, err
		}
		rows, err = s.q.ListProvisionedUsers(ctx, dbgen.ListProvisionedUsersParams{OrganizationID: &organizationID, Lim: lim, Off: off})
	}
	if err != nil {
		return nil, 0, err
	}
	out := make([]userRow, len(rows))
	for i, r := range rows {
		out[i] = userRow(r)
	}
	return out, int(total), nil
}

func (s *Service) tagProvisionedTx(ctx context.Context, tx pgx.Tx, id uuid.UUID, externalID string) error {
	var ext *string
	if externalID != "" {
		ext = &externalID
	}
	return s.q.WithTx(tx).TagProvisionedUser(ctx, dbgen.TagProvisionedUserParams{
		ExternalID: ext,
		ID:         id,
	})
}

// toResource renders a user row as a SCIM core User.
func (h *Handler) toResource(r *http.Request, u *userRow) map[string]any {
	display := ""
	if u.DisplayName != nil {
		display = *u.DisplayName
	}
	res := map[string]any{
		"schemas":  []string{schemaUser},
		"id":       u.ID.String(),
		"userName": u.Email,
		"active":   u.Status == "active",
		"emails":   []map[string]any{{"value": u.Email, "primary": true, "type": "work"}},
		"meta": map[string]any{
			"resourceType": "User",
			"created":      u.CreatedAt.UTC().Format(time.RFC3339),
			"lastModified": u.UpdatedAt.UTC().Format(time.RFC3339),
			"location":     h.location(r, "/Users/"+u.ID.String()),
		},
	}
	if display != "" {
		res["displayName"] = display
		res["name"] = map[string]any{"formatted": display}
	}
	if u.ExternalID != nil && *u.ExternalID != "" {
		res["externalId"] = *u.ExternalID
	}
	return res
}

func parseUserNameFilter(filter string) (string, error) {
	return parseEqualityFilter(filter, "userName")
}

func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request) {
	tid, ok := organizationFromCtx(r.Context())
	if !ok {
		writeSCIMErr(w, http.StatusUnauthorized, "no organization")
		return
	}
	start, count := listWindow(r)
	email, err := parseUserNameFilter(r.URL.Query().Get("filter"))
	if err != nil {
		writeSCIMTypedErr(w, http.StatusBadRequest, "invalidFilter", "Only userName eq \"value\" is supported.")
		return
	}

	rows, total, err := h.Service.listProvisioned(r.Context(), tid, email, start, count)
	if err != nil {
		writeSCIMErr(w, http.StatusInternalServerError, "list failed")
		return
	}
	resources := make([]map[string]any, 0, len(rows))
	for i := range rows {
		resources = append(resources, h.toResource(r, &rows[i]))
	}
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":      []string{schemaListResp},
		"totalResults": total,
		"startIndex":   start,
		"itemsPerPage": len(resources),
		"Resources":    resources,
	})
}

type scimUserPayload struct {
	Source      map[string]any `json:"-"`
	UserName    string         `json:"userName"`
	DisplayName string         `json:"displayName"`
	ExternalID  string         `json:"externalId"`
	Active      *bool          `json:"active"`
	Name        *scimName      `json:"name"`
	Emails      []scimEmail    `json:"emails"`
}

type scimName struct {
	Formatted  string `json:"formatted"`
	GivenName  string `json:"givenName"`
	FamilyName string `json:"familyName"`
}

type scimEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary"`
}

func (p scimUserPayload) email() string {
	if p.UserName != "" {
		return strings.TrimSpace(p.UserName)
	}
	for _, e := range p.Emails {
		if e.Primary && e.Value != "" {
			return strings.TrimSpace(e.Value)
		}
	}
	if len(p.Emails) > 0 {
		return strings.TrimSpace(p.Emails[0].Value)
	}
	return ""
}

func (p scimUserPayload) display() string {
	if p.DisplayName != "" {
		return p.DisplayName
	}
	if p.Name != nil {
		if p.Name.Formatted != "" {
			return p.Name.Formatted
		}
		full := strings.TrimSpace(p.Name.GivenName + " " + p.Name.FamilyName)
		if full != "" {
			return full
		}
	}
	return ""
}

func (h *Handler) createUser(w http.ResponseWriter, r *http.Request) {
	tid, ok := organizationFromCtx(r.Context())
	if !ok {
		writeSCIMErr(w, http.StatusUnauthorized, "no organization")
		return
	}
	var p scimUserPayload
	if !decodeSCIMBody(w, r, &p) {
		return
	}
	profile, err := h.Service.profile(r.Context(), tid, p.Source, false)
	if err != nil {
		writeSCIMTypedErr(w, http.StatusBadRequest, "invalidValue", "Directory mapping validation failed")
		return
	}
	email := p.email()
	if mapped, ok := profile["email"].(string); ok {
		email = mapped
	}
	display := p.display()
	if mapped, ok := profile["display_name"].(string); ok {
		display = mapped
	}
	if email == "" {
		writeSCIMErr(w, http.StatusBadRequest, "userName (email) is required")
		return
	}
	ctx := r.Context()
	// Someone already at home in the organization (invited, or signed in with
	// single sign-on) is adopted rather than refused as a duplicate.
	if existing, err := h.Service.q.HomeUserByEmail(ctx, dbgen.HomeUserByEmailParams{OrganizationID: tid, Email: email}); err == nil {
		c := userChange{profile: profile, tag: &p.ExternalID, adopted: true}
		if display != "" {
			c.in.DisplayName = &display
		}
		if st := statusFromActive(p.Active); st != "" {
			c.in.Status = &st
		}
		if !h.applyUserChange(w, r, tid, existing, c, "user.updated") {
			return
		}
		row, err := h.Service.getProvisioned(ctx, tid, existing)
		if err != nil {
			writeSCIMErr(w, http.StatusNotFound, "user not found")
			return
		}
		writeSCIM(w, http.StatusCreated, h.toResource(r, row))
		return
	} else if !errors.Is(err, pgx.ErrNoRows) {
		writeSCIMErr(w, http.StatusInternalServerError, "create failed")
		return
	}
	if err := domainverify.CheckNewAccount(ctx, h.Service.users.Pool(), tid, email); err != nil {
		if errors.Is(err, errs.ErrUserDomainManaged) {
			writeSCIMErr(w, http.StatusConflict, "userName is on a domain another organization manages")
			return
		}
		writeSCIMErr(w, http.StatusInternalServerError, "create failed")
		return
	}
	userID, err := h.Service.createProvisioned(ctx, scimActor(r), tid, newUser{
		email: email, display: display, externalID: p.ExternalID, active: p.Active == nil || *p.Active, profile: profile,
	})
	if err != nil {
		writeRefusal(w, err)
		return
	}
	row, err := h.Service.getProvisioned(ctx, tid, userID)
	if err != nil {
		writeSCIMErr(w, http.StatusInternalServerError, "reload failed")
		return
	}
	writeSCIM(w, http.StatusCreated, h.toResource(r, row))
}

func (h *Handler) getUser(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := h.scimTarget(w, r)
	if !ok {
		return
	}
	row, err := h.Service.getProvisioned(r.Context(), tid, id)
	if err != nil {
		writeSCIMErr(w, http.StatusNotFound, "user not found")
		return
	}
	writeSCIM(w, http.StatusOK, h.toResource(r, row))
}

func (h *Handler) replaceUser(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := h.scimTarget(w, r)
	if !ok {
		return
	}
	var p scimUserPayload
	if !decodeSCIMBody(w, r, &p) {
		return
	}
	profile, err := h.Service.profile(r.Context(), tid, p.Source, false)
	if err != nil {
		writeSCIMTypedErr(w, http.StatusBadRequest, "invalidValue", "Directory mapping validation failed")
		return
	}
	c := userChange{profile: profile, email: p.email()}
	if d := p.display(); d != "" {
		c.in.DisplayName = &d
	}
	status := statusFromActive(p.Active)
	if status != "" {
		c.in.Status = &status
	}
	ext := p.ExternalID // PUT is a full replace: externalId is authoritative
	c.tag = &ext
	if !h.applyUserChange(w, r, tid, id, c, "user.updated") {
		return
	}
	row, err := h.Service.getProvisioned(r.Context(), tid, id)
	if err != nil {
		writeSCIMErr(w, http.StatusNotFound, "user not found")
		return
	}
	writeSCIM(w, http.StatusOK, h.toResource(r, row))
}

func (h *Handler) deleteUser(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := h.scimTarget(w, r)
	if !ok {
		return
	}
	// Confirm the user belongs to this organization before soft-deleting.
	if _, err := h.Service.getProvisioned(r.Context(), tid, id); err != nil {
		writeSCIMErr(w, http.StatusNotFound, "user not found")
		return
	}
	if err := h.Service.deprovision(r.Context(), scimActor(r), tid, id); err != nil {
		if errors.Is(err, errOwnerUnchangeable) {
			writeSCIMErr(w, http.StatusForbidden, ownerUnchangeable)
			return
		}
		writeSCIMErr(w, http.StatusNotFound, "user not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// newUser is an account a SCIM create provisions.
type newUser struct {
	email, display, externalID string
	active                     bool
	profile                    map[string]any
}

// createProvisioned creates the account nu, tagged as the directory's, with
// its mapped profile and its evidence, recorded as actor's, in one
// transaction, and returns its ID. An identity provider can create it already
// deactivated. Every error is a *scimRefusal.
func (s *Service) createProvisioned(ctx context.Context, actor audit.Actor, organizationID uuid.UUID, nu newUser) (uuid.UUID, error) {
	failed := refusal(http.StatusInternalServerError, "", "create failed")
	tx, err := s.users.Pool().Begin(ctx)
	if err != nil {
		return uuid.Nil, failed
	}
	defer tx.Rollback(ctx)
	u, err := s.users.CreateWithCredentialTx(ctx, tx, user.CreateInput{
		OrganizationID: organizationID,
		Email:          nu.email,
		DisplayName:    nu.display,
	}, "")
	if err != nil {
		if errors.Is(err, errs.ErrAuthEmailExists) || errors.Is(err, errs.ErrConflict) {
			return uuid.Nil, refusal(http.StatusConflict, "", "userName already exists")
		}
		return uuid.Nil, refusal(http.StatusBadRequest, "", "create failed")
	}
	if err := s.tagProvisionedTx(ctx, tx, u.ID, nu.externalID); err != nil {
		return uuid.Nil, refusal(http.StatusInternalServerError, "", "tagging failed")
	}
	if s.mapper != nil {
		if err := s.mapper.StoreProfile(ctx, tx, organizationID, u.ID, "scim:"+organizationID.String(), nu.profile); err != nil {
			return uuid.Nil, refusal(http.StatusInternalServerError, "", "Profile mapping could not be saved")
		}
	}
	if !nu.active {
		suspended := "suspended"
		if _, err := s.users.UpdateTx(ctx, tx, u.ID, user.UpdateInput{Status: &suspended}); err != nil {
			return uuid.Nil, failed
		}
		if err := s.q.WithTx(tx).SetScimSuspension(ctx, dbgen.SetScimSuspensionParams{OrganizationID: &organizationID, ID: u.ID}); err != nil {
			return uuid.Nil, failed
		}
	}
	if err := recordUserEvidence(ctx, tx, actor, organizationID, u.ID, "user.created",
		map[string]any{"email": u.Email, "active": nu.active}); err != nil {
		return uuid.Nil, failed
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, failed
	}
	return u.ID, nil
}

// errOwnerUnchangeable refuses deprovisioning an owner.
var errOwnerUnchangeable = errors.New("scim: the account owns the organization")

// deprovision soft-deletes a SCIM-managed user, ending every way they sign
// in, and records it and what they leave behind (OffboardTx), as actor's, in
// the same transaction. An owner is refused with errOwnerUnchangeable.
func (s *Service) deprovision(ctx context.Context, actor audit.Actor, organizationID, userID uuid.UUID) error {
	tx, err := s.users.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	state, err := s.q.WithTx(tx).ProvisionedUserState(ctx, dbgen.ProvisionedUserStateParams{OrganizationID: organizationID, ID: userID})
	if err != nil {
		return err
	}
	if state.Owner {
		return errOwnerUnchangeable
	}
	if err := s.users.SoftDeleteTx(ctx, tx, userID); err != nil {
		return err
	}
	if _, err := auth.EndSignIns(ctx, tx, s.signals, userID, sessionsignal.ReasonDeprovisioned); err != nil {
		return err
	}
	if err := recordUserEvidence(ctx, tx, actor, organizationID, userID, "user.deleted", nil); err != nil {
		return err
	}
	if err := s.users.OffboardTx(ctx, tx, organizationID, userID, actor); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
