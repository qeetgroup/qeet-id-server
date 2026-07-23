// Package copilotmanifest embeds the canonical Qeet ID copilot tool manifest.
// Both the Go orchestrator and the frontend tool-registry load from it; the
// tool names are the contract between them (a QA parity test asserts they match).
package copilotmanifest

import _ "embed"

// ToolsManifestJSON is the raw content of tools.manifest.json, the canonical
// catalog of copilot tools, embedded at build time.
//
//go:embed tools.manifest.json
var ToolsManifestJSON []byte
