package qeetai

import (
	"encoding/json"
	"fmt"

	qeetaimanifest "github.com/qeetgroup/qeet-id-server/api/qeetai"
	"github.com/qeetgroup/qeet-id-server/internal/platform/ai"
)

// changeToolsEnabled controls whether the model is offered tools that change
// anything. It is off: the assistant only reads and explains. Change tools stay
// in the manifest until assistant actions have a server-side boundary.
const changeToolsEnabled = false

// toolManifestEntry is one tool in tools.manifest.json. Every tool must set
// Mutates; a missing value is a manifest error, not a tool silently offered.
type toolManifestEntry struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
	Mutates     *bool           `json:"mutates"`
}

type toolManifest struct {
	Tools []toolManifestEntry `json:"tools"`
}

// loadToolDefs parses the embedded tool manifest into the ai.ToolDef values
// offered to the model, leaving out change tools while changeToolsEnabled is
// off. Tools never run on the server; the browser runs them under the user's
// own token.
func loadToolDefs() ([]ai.ToolDef, error) {
	var m toolManifest
	if err := json.Unmarshal(qeetaimanifest.ToolsManifestJSON, &m); err != nil {
		return nil, fmt.Errorf("qeetai: parse tools manifest: %w", err)
	}
	defs := make([]ai.ToolDef, 0, len(m.Tools))
	for _, t := range m.Tools {
		if t.Mutates == nil {
			return nil, fmt.Errorf("qeetai: tool %q in the manifest doesn't declare mutates", t.Name)
		}
		if *t.Mutates && !changeToolsEnabled {
			continue
		}
		defs = append(defs, ai.ToolDef{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.InputSchema,
		})
	}
	return defs, nil
}
