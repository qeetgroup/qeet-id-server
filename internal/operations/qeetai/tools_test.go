package qeetai

import (
	"encoding/json"
	"strings"
	"testing"

	qeetaimanifest "github.com/qeetgroup/qeet-id-server/api/qeetai"
)

// manifestTools reads every tool in the embedded manifest, with the fields
// these tests check.
func manifestTools(t *testing.T) []struct {
	Name        string  `json:"name"`
	Capability  *string `json:"capability"`
	Destructive bool    `json:"destructive"`
	Mutates     *bool   `json:"mutates"`
} {
	t.Helper()
	var m struct {
		Tools []struct {
			Name        string  `json:"name"`
			Capability  *string `json:"capability"`
			Destructive bool    `json:"destructive"`
			Mutates     *bool   `json:"mutates"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(qeetaimanifest.ToolsManifestJSON, &m); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	return m.Tools
}

// Every tool says whether it changes anything, and one that looks like a
// change (destructive, or gated on a .write capability) can't say it doesn't:
// a new change tool can't slip past the read-only switch by leaving it out.
func TestEveryToolDeclaresWhetherItChangesAnything(t *testing.T) {
	for _, tool := range manifestTools(t) {
		if tool.Mutates == nil {
			t.Errorf("%s: no mutates in the manifest", tool.Name)
			continue
		}
		looksLikeChange := tool.Destructive || (tool.Capability != nil && strings.HasSuffix(*tool.Capability, ".write"))
		if looksLikeChange && !*tool.Mutates {
			t.Errorf("%s: changes state (destructive or a .write capability) but says mutates: false", tool.Name)
		}
	}
}

// While change tools are switched off, the model is offered only the tools
// that read or explain, and still every one of those.
func TestTheModelIsOfferedNoChangeTool(t *testing.T) {
	defs, err := loadToolDefs()
	if err != nil {
		t.Fatalf("load tools: %v", err)
	}
	offered := map[string]bool{}
	for _, d := range defs {
		offered[d.Name] = true
	}
	readOnly := 0
	for _, tool := range manifestTools(t) {
		changes := tool.Mutates == nil || *tool.Mutates
		if changes && offered[tool.Name] {
			t.Errorf("%s changes state but is offered to the model", tool.Name)
		}
		if !changes {
			readOnly++
			if !offered[tool.Name] {
				t.Errorf("read-only tool %s is not offered to the model", tool.Name)
			}
		}
	}
	if readOnly == 0 {
		t.Fatal("the manifest has no read-only tools to offer")
	}
}

// The standing instruction doesn't tell the model it can make changes, and
// tells it what to do when asked to.
func TestTheSystemPromptDescribesAReadOnlyAssistant(t *testing.T) {
	lower := strings.ToLower(systemPrompt)
	for _, claim := range []string{"manage roles", "create oidc clients", "destructive operations", "confirmation dialog"} {
		if strings.Contains(lower, claim) {
			t.Errorf("system prompt still says %q", claim)
		}
	}
	if !strings.Contains(lower, "can't make changes") {
		t.Error("system prompt doesn't say the assistant can't make changes")
	}
}
