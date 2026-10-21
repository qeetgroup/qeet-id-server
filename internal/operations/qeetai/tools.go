package qeetai

import (
	"encoding/json"
	"fmt"

	qeetaimanifest "github.com/qeetgroup/qeet-id-server/api/qeetai"
	"github.com/qeetgroup/qeet-id-server/internal/platform/ai"
)

// changeToolsEnabled is whether the model is offered tools that change
// anything. Off for 1.0: the assistant only reads and explains, and the console
// runs no change tool either (its ASSISTANT_CHANGE_TOOLS_ENABLED). The change
// tools stay in the manifest for when a server-side boundary for assistant
// actions exists.
const changeToolsEnabled = false

// toolManifestEntry is the JSON shape of one tool entry in tools.manifest.json.
type toolManifestEntry struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
	// Mutates is whether the tool changes anything. Every tool must say; one
	// that doesn't is a manifest error rather than a tool silently offered.
	Mutates *bool `json:"mutates"`
}

type toolManifest struct {
	Tools []toolManifestEntry `json:"tools"`
}

// loadToolDefs parses the embedded tools.manifest.json and returns the tools
// the model is offered, as neutral ai.ToolDef values. Both the Anthropic and
// OpenAI provider wrappers accept this format and convert to their own wire
// representation. While changeToolsEnabled is off, a tool that changes
// anything is left out, so the model can't ask for one. The server NEVER
// provides a run() implementation — tools execute client-side under the user's
// own token (RBAC/audit inherited, never bypassed).
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
