package group

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

// An update names only what changes, so a missing parent_id must not read as
// "make it top-level"; only an explicit null does that.
func TestUpdateInputTellsAMissingParentFromNull(t *testing.T) {
	id := uuid.New()
	for _, c := range []struct {
		body    string
		set     bool
		id      *uuid.UUID
		name    *string
		wantErr bool
	}{
		{body: `{}`},
		{body: `{"name": "Platform"}`, name: ptr("Platform")},
		{body: `{"parent_id": null}`, set: true},
		{body: `{"parent_id": "` + id.String() + `"}`, set: true, id: &id},
		{body: `{"parent_id": "not-a-uuid"}`, wantErr: true},
	} {
		var in UpdateInput
		err := json.Unmarshal([]byte(c.body), &in)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: decoded without error", c.body)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", c.body, err)
		}
		if in.ParentID.Set != c.set {
			t.Errorf("%s: Set = %v, want %v", c.body, in.ParentID.Set, c.set)
		}
		if (in.ParentID.ID == nil) != (c.id == nil) || (c.id != nil && *in.ParentID.ID != *c.id) {
			t.Errorf("%s: ID = %v, want %v", c.body, in.ParentID.ID, c.id)
		}
		if (in.Name == nil) != (c.name == nil) || (c.name != nil && *in.Name != *c.name) {
			t.Errorf("%s: Name = %v, want %v", c.body, in.Name, c.name)
		}
		if in.Description != nil {
			t.Errorf("%s: Description = %q, want unset", c.body, *in.Description)
		}
	}
}

func ptr(s string) *string { return &s }
