package scim

import (
	"net/http"
)

func (h *Handler) serviceProviderConfig(w http.ResponseWriter, r *http.Request) {
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":          []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri": h.location(r, ""),
		"patch":            map[string]any{"supported": true},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": maxPageCount},
		"changePassword":   map[string]any{"supported": false},
		"sort":             map[string]any{"supported": false},
		"etag":             map[string]any{"supported": false},
		"authenticationSchemes": []map[string]any{{
			"type":        "oauthbearertoken",
			"name":        "OAuth Bearer Token",
			"description": "Authentication via the organization SCIM bearer token.",
			"primary":     true,
		}},
		"meta": map[string]any{"resourceType": "ServiceProviderConfig", "location": h.location(r, "/ServiceProviderConfig")},
	})
}

func (h *Handler) resourceTypes(w http.ResponseWriter, r *http.Request) {
	userType := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
		"id":          "User",
		"name":        "User",
		"endpoint":    "/Users",
		"description": "User Account",
		"schema":      schemaUser,
		"meta":        map[string]any{"resourceType": "ResourceType", "location": h.location(r, "/ResourceTypes/User")},
	}
	groupType := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
		"id":          "Group",
		"name":        "Group",
		"endpoint":    "/Groups",
		"description": "Group",
		"schema":      schemaGroup,
		"meta":        map[string]any{"resourceType": "ResourceType", "location": h.location(r, "/ResourceTypes/Group")},
	}
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":      []string{schemaListResp},
		"totalResults": 2,
		"startIndex":   1,
		"itemsPerPage": 2,
		"Resources":    []map[string]any{userType, groupType},
	})
}

func (h *Handler) schemas(w http.ResponseWriter, r *http.Request) {
	userSchema := map[string]any{
		"id":          schemaUser,
		"name":        "User",
		"description": "User Account",
		"attributes": []map[string]any{
			{"name": "userName", "type": "string", "required": true, "uniqueness": "server", "mutability": "readWrite"},
			{"name": "displayName", "type": "string", "required": false, "mutability": "readWrite"},
			{"name": "active", "type": "boolean", "required": false, "mutability": "readWrite"},
			{"name": "externalId", "type": "string", "required": false, "mutability": "readWrite"},
		},
		"meta": map[string]any{"resourceType": "Schema", "location": h.location(r, "/Schemas/"+schemaUser)},
	}
	groupSchema := map[string]any{
		"id":          schemaGroup,
		"name":        "Group",
		"description": "Group",
		"attributes": []map[string]any{
			{"name": "displayName", "type": "string", "required": true, "uniqueness": "none", "mutability": "readWrite"},
			{"name": "externalId", "type": "string", "required": false, "mutability": "readWrite"},
			{
				"name":        "members",
				"type":        "complex",
				"multiValued": true,
				"required":    false,
				"mutability":  "readWrite",
				"subAttributes": []map[string]any{
					{"name": "value", "type": "string", "mutability": "immutable"},
					{"name": "display", "type": "string", "mutability": "readOnly"},
					{"name": "$ref", "type": "reference", "mutability": "immutable"},
				},
			},
		},
		"meta": map[string]any{"resourceType": "Schema", "location": h.location(r, "/Schemas/"+schemaGroup)},
	}
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":      []string{schemaListResp},
		"totalResults": 2,
		"startIndex":   1,
		"itemsPerPage": 2,
		"Resources":    []map[string]any{userSchema, groupSchema},
	})
}
