package copilot

import (
	"encoding/json"
	"fmt"

	copilotmanifest "github.com/qeetgroup/qeet-id-server/api/copilot"
	"github.com/qeetgroup/qeet-id-server/internal/platform/ai"
)

// toolManifestEntry is the JSON shape of one tool entry in tools.manifest.json.
type toolManifestEntry struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

type toolManifest struct {
	Tools []toolManifestEntry `json:"tools"`
}

// loadToolDefs parses the embedded tools.manifest.json and returns a slice of
// neutral ai.ToolDef values. Both the Anthropic and OpenAI provider wrappers
// accept this format and convert to their own wire representation.
// The server NEVER provides a run() implementation — tools execute client-side
// under the user's own token (RBAC/audit inherited, never bypassed).
func loadToolDefs() ([]ai.ToolDef, error) {
	var m toolManifest
	if err := json.Unmarshal(copilotmanifest.ToolsManifestJSON, &m); err != nil {
		return nil, fmt.Errorf("copilot: parse tools manifest: %w", err)
	}
	defs := make([]ai.ToolDef, 0, len(m.Tools))
	for _, t := range m.Tools {
		defs = append(defs, ai.ToolDef{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.InputSchema,
		})
	}
	return defs, nil
}
