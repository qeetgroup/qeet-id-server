// Package copilotmanifest exposes the canonical Qeet ID copilot tool manifest
// as an embedded byte slice. Both the Go orchestrator (tool definitions for the
// Anthropic Messages API) and the frontend tool-registry (which attaches run())
// load from this file. Names are the contract between the two sides; a QA
// parity test asserts they match.
package copilotmanifest

import _ "embed"

// ToolsManifestJSON is the raw content of tools.manifest.json, the canonical
// catalog of all 21 copilot tools. Embedded at build time so no file-system
// access is required at runtime.
//
//go:embed tools.manifest.json
var ToolsManifestJSON []byte
