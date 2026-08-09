// Package qeetaimanifest embeds the canonical Qeet ID qeetai tool manifest.
// Both the Go orchestrator and the frontend tool-registry load from it; the
// tool names are the contract between them (a QA parity test asserts they match).
package qeetaimanifest

import _ "embed"

// ToolsManifestJSON is the raw content of tools.manifest.json, the canonical
// catalog of qeetai tools, embedded at build time.
//
//go:embed tools.manifest.json
var ToolsManifestJSON []byte
