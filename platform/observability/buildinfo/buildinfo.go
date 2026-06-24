// Package buildinfo exposes the binary's build metadata. The values are stamped
// at build time via -ldflags (-X) by the Makefile, Dockerfile, and release CI;
// they keep their defaults under `go run`/`go test`, so dev and tests always
// work without a build step.
//
// Stamp with, e.g.:
//
//	go build -ldflags "\
//	  -X github.com/qeetgroup/qeet-id/platform/buildinfo.Version=v1.2.3 \
//	  -X github.com/qeetgroup/qeet-id/platform/buildinfo.Commit=$(git rev-parse --short HEAD) \
//	  -X github.com/qeetgroup/qeet-id/platform/buildinfo.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
package buildinfo

import "runtime/debug"

// Stamped at link time; defaults are used for `go run`/tests.
var (
	Version = "dev"     //nolint:gochecknoglobals // set via -ldflags -X
	Commit  = "none"    //nolint:gochecknoglobals // set via -ldflags -X
	Date    = "unknown" //nolint:gochecknoglobals // set via -ldflags -X
)

// Info is the structured build metadata surfaced on /healthz and exported as a
// Prometheus build_info gauge.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"go_version"`
}

// Get returns the build metadata. When -ldflags did not set Commit (e.g. a bare
// `go build`), it falls back to the VCS revision the Go toolchain embeds.
func Get() Info {
	i := Info{Version: Version, Commit: Commit, Date: Date}
	if bi, ok := debug.ReadBuildInfo(); ok {
		i.GoVersion = bi.GoVersion
		if i.Commit == "none" {
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" {
					i.Commit = s.Value
				}
			}
		}
	}
	return i
}
