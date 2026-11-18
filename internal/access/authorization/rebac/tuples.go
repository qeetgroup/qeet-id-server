package rebac

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rebac/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Tuple is the API/read projection of a stored relationship.
type Tuple struct {
	ID       uuid.UUID `json:"id"`
	Object   string    `json:"object"`
	Relation string    `json:"relation"`
	Subject  string    `json:"subject"`
	// SubjectName names a user: subject who belongs to the organization.
	SubjectName string `json:"subject_name,omitempty"`
}

func subjectString(typ, id, rel string) string {
	if rel == "" {
		return typ + ":" + id
	}
	return typ + ":" + id + "#" + rel
}

// Write upserts a relationship tuple, recorded as actor's. object = "type:id",
// subject = "user:<id>" or "type:id#relation".
func (s *Service) Write(ctx context.Context, organizationID uuid.UUID, object, relation, subject string, actor audit.Actor) (*Tuple, error) {
	o, ok := parseObject(object)
	if !ok {
		return nil, errs.ErrReBACObjectInvalid
	}
	subj, ok := parseSubject(subject)
	if !ok {
		return nil, ErrSubjectInvalid
	}
	if strings.TrimSpace(relation) == "" {
		return nil, ErrRelationRequired
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	id, err := s.q.WithTx(tx).InsertRelationTuple(ctx, dbgen.InsertRelationTupleParams{
		OrganizationID:  organizationID,
		ObjectType:      o.Type,
		ObjectID:        o.ID,
		Relation:        relation,
		SubjectType:     subj.Type,
		SubjectID:       subj.ID,
		SubjectRelation: subj.Relation,
	})
	if err != nil {
		return nil, err
	}
	tuple := &Tuple{ID: id, Object: object, Relation: relation, Subject: subjectString(subj.Type, subj.ID, subj.Relation)}
	metadata := map[string]any{"object": tuple.Object, "relation": tuple.Relation, "subject": tuple.Subject}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "rebac.tuple_written", "relation_tuple", tuple.ID, metadata)); err != nil {
		return nil, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: tuple.ID, Topic: "authorization.events", EventType: "rebac.tuple_written", Payload: map[string]any{"tuple_id": tuple.ID, "organization_id": organizationID, "object": tuple.Object, "relation": tuple.Relation, "subject": tuple.Subject}}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return tuple, nil
}

// Delete removes one of the organization's relationship tuples, recorded as actor's.
func (s *Service) Delete(ctx context.Context, id, organizationID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	row, err := s.q.WithTx(tx).DeleteRelationTuple(ctx, dbgen.DeleteRelationTupleParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound
	}
	if err != nil {
		return err
	}
	metadata := map[string]any{
		"object":   row.ObjectType + ":" + row.ObjectID,
		"relation": row.Relation,
		"subject":  subjectString(row.SubjectType, row.SubjectID, row.SubjectRelation),
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "rebac.tuple_deleted", "relation_tuple", id, metadata)); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: id, Topic: "authorization.events", EventType: "rebac.tuple_deleted", Payload: map[string]any{"tuple_id": id, "organization_id": organizationID}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// List returns the tuples on a given object (type:id).
func (s *Service) List(ctx context.Context, organizationID uuid.UUID, object string) ([]Tuple, error) {
	o, ok := parseObject(object)
	if !ok {
		return nil, errs.ErrReBACObjectInvalid
	}
	rows, err := s.q.ListRelationTuplesByObject(ctx, dbgen.ListRelationTuplesByObjectParams{
		OrganizationID: organizationID,
		ObjectType:     o.Type,
		ObjectID:       o.ID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]Tuple, 0, len(rows))
	people := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, Tuple{
			ID:       row.ID,
			Object:   object,
			Relation: row.Relation,
			Subject:  subjectString(row.SubjectType, row.SubjectID, row.SubjectRelation),
		})
		if row.SubjectType == "user" {
			people = append(people, row.SubjectID)
		}
	}
	names, err := s.namePeople(ctx, organizationID, people)
	if err != nil {
		return nil, err
	}
	for i := range out {
		if id, ok := strings.CutPrefix(out[i].Subject, "user:"); ok {
			out[i].SubjectName = names[id]
		}
	}
	return out, nil
}

// namePeople names those of ids, user: subject ids, who belong to organizationID.
func (s *Service) namePeople(ctx context.Context, organizationID uuid.UUID, ids []string) (map[string]string, error) {
	parsed := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if u, err := uuid.Parse(id); err == nil {
			parsed = append(parsed, u)
		}
	}
	names := map[string]string{}
	if len(parsed) == 0 {
		return names, nil
	}
	rows, err := s.q.NamePeople(ctx, dbgen.NamePeopleParams{Ids: parsed, OrganizationID: &organizationID})
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		names[r.ID.String()] = r.Name
	}
	return names, nil
}

// ListBySubject returns every tuple in which subject (type:id) appears, the
// reverse of List.
func (s *Service) ListBySubject(ctx context.Context, organizationID uuid.UUID, subject string) ([]Tuple, error) {
	subj, ok := parseSubject(subject)
	if !ok {
		return nil, ErrSubjectInvalid
	}
	rows, err := s.q.ListRelationTuplesBySubject(ctx, dbgen.ListRelationTuplesBySubjectParams{
		OrganizationID: organizationID,
		SubjectType:    subj.Type,
		SubjectID:      subj.ID,
	})
	if err != nil {
		return nil, err
	}
	name := ""
	if subj.Type == "user" {
		names, err := s.namePeople(ctx, organizationID, []string{subj.ID})
		if err != nil {
			return nil, err
		}
		name = names[subj.ID]
	}
	out := make([]Tuple, 0, len(rows))
	for _, row := range rows {
		out = append(out, Tuple{
			ID:          row.ID,
			Object:      graphNodeID(row.ObjectType, row.ObjectID),
			Relation:    row.Relation,
			Subject:     subjectString(subj.Type, subj.ID, row.SubjectRelation),
			SubjectName: name,
		})
	}
	return out, nil
}
