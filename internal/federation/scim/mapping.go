package scim

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type ProfileMapper interface {
	MapProfile(context.Context, uuid.UUID, string, map[string]any, bool) (map[string]any, error)
	StoreProfile(context.Context, pgx.Tx, uuid.UUID, uuid.UUID, string, map[string]any) error
}

func (service *Service) SetProfileMapper(mapper ProfileMapper) { service.mapper = mapper }

func (payload *scimUserPayload) UnmarshalJSON(raw []byte) error {
	type plainPayload scimUserPayload
	var decoded plainPayload
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	*payload = scimUserPayload(decoded)
	return json.Unmarshal(raw, &payload.Source)
}

func (service *Service) profile(ctx context.Context, tenantID uuid.UUID, source map[string]any, partial bool) (map[string]any, error) {
	if service.mapper == nil {
		return nil, nil
	}
	return service.mapper.MapProfile(ctx, tenantID, "scim:"+tenantID.String(), source, partial)
}

func patchProfileSource(body patchBody) map[string]any {
	source := map[string]any{}
	for _, operation := range body.Operations {
		kind := strings.ToLower(operation.Op)
		if kind != "add" && kind != "replace" && kind != "remove" {
			continue
		}
		path := strings.Trim(operation.Path, `"`)
		var value any
		if kind != "remove" {
			if json.Unmarshal(operation.Value, &value) != nil {
				continue
			}
		}
		if path == "" {
			if object, ok := value.(map[string]any); ok {
				for key, value := range object {
					source[key] = value
				}
			}
			continue
		}
		if strings.Contains(path, "[") || strings.Contains(path, ":") {
			source[path] = value
			continue
		}
		parts := strings.Split(path, ".")
		if len(parts) > 8 {
			continue
		}
		current := source
		for _, part := range parts[:len(parts)-1] {
			nested, ok := current[part].(map[string]any)
			if !ok {
				nested = map[string]any{}
				current[part] = nested
			}
			current = nested
		}
		current[parts[len(parts)-1]] = value
	}
	return source
}
