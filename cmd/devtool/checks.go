package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// The pinned tool versions and scanner images, each overridable by the variable named (in the shell
// or .env); they are read when used, after .env is loaded. Keep the defaults in step with
// .github/workflows/ci.yml.
func golangciVersion() string    { return envOr("GOLANGCI_VERSION", "v2.15.0") }
func sqlcVersion() string        { return envOr("SQLC_VERSION", "v1.31.1") }
func govulncheckVersion() string { return envOr("GOVULNCHECK_VERSION", "v1.9.0") }
func gosecVersion() string       { return envOr("GOSEC_VERSION", "v2.30.0") }
func gosecXTools() string        { return envOr("GOSEC_XTOOLS_VERSION", "v0.52.0") }
func scanImageTag() string       { return envOr("SCAN_IMAGE_TAG", "qeet-id-server:scan") }
func gitleaksImage() string {
	return envOr("GITLEAKS_IMAGE", "ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f")
}
func trivyImage() string {
	return envOr("TRIVY_IMAGE", "aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb")
}

func lint() error {
	if err := run("go", "vet", "./..."); err != nil {
		return err
	}
	return golangci("run", "--build-tags=integration", "./...")
}

func vuln() error {
	return run("go", "run", "golang.org/x/vuln/cmd/govulncheck@"+govulncheckVersion(), "./cmd/...", "./internal/...")
}

// cachedTool returns the tool's binary in GOPATH/bin under its versioned name, building it the
// first time with build (given the directory to put the binary in).
func cachedTool(name, version string, build func(bin string) error) (string, error) {
	gopath, err := output("go", "env", "GOPATH")
	if err != nil {
		return "", err
	}
	bin := exe(filepath.Join(gopath, "bin", name+"-"+version))
	if _, err := os.Stat(bin); err == nil {
		return bin, nil
	}
	if err := os.MkdirAll(filepath.Dir(bin), 0o750); err != nil {
		return "", err
	}
	return bin, build(bin)
}

// sqlcRun runs the pinned sqlc, built once and cached in GOPATH/bin.
func sqlcRun(args ...string) error {
	bin, err := cachedTool("sqlc", sqlcVersion(), func(bin string) error {
		dir, err := os.MkdirTemp("", "sqlc-build")
		if err != nil {
			return err
		}
		defer func() { _ = os.RemoveAll(dir) }()
		if err := runIn("", []string{"GOBIN=" + dir}, os.Stdout, "go", "install", "github.com/sqlc-dev/sqlc/cmd/sqlc@"+sqlcVersion()); err != nil {
			return err
		}
		return os.Rename(exe(filepath.Join(dir, "sqlc")), bin)
	})
	if err != nil {
		return err
	}
	return run(bin, args...)
}

// sqlcCheck fails if a queries.sql isn't listed in sqlc.yaml (its dbgen/ would never be checked),
// then if any dbgen/ differs from what sqlc generates.
func sqlcCheck() error {
	cfg, err := os.ReadFile("sqlc.yaml")
	if err != nil {
		return err
	}
	listed := map[string]bool{}
	for _, line := range strings.Split(string(cfg), "\n") {
		if q, ok := strings.CutPrefix(strings.TrimSpace(line), "queries: "); ok {
			listed[q] = true
		}
	}
	err = filepath.WalkDir("internal", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "queries.sql" {
			return err
		}
		if p := filepath.ToSlash(path); !listed[p] {
			return fmt.Errorf("sqlc-check: %s is not listed in sqlc.yaml", p)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return sqlcRun("diff")
}

// sast runs gosec built against a current x/tools, as CI does (the released binary can't read this
// Go version's export data), cached in GOPATH/bin.
func sast() error {
	bin, err := cachedTool("gosec", gosecVersion(), func(bin string) error {
		dir, err := os.MkdirTemp("", "gosec-build")
		if err != nil {
			return err
		}
		defer func() { _ = os.RemoveAll(dir) }()
		for _, args := range [][]string{
			{"mod", "init", "gosec-build"},
			{"get", "github.com/securego/gosec/v2/cmd/gosec@" + gosecVersion(), "golang.org/x/tools@" + gosecXTools()},
			{"build", "-o", bin, "github.com/securego/gosec/v2/cmd/gosec"},
		} {
			if err := runIn(dir, nil, os.Stdout, "go", args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return run(bin, "-quiet", "-conf", ".gosec.json", "-exclude-dir=.*dbgen", "-exclude-generated", "./...")
}

// secretScan runs gitleaks, as CI does, over the git history and then the working tree as it is
// (uncommitted work too), skipping what .gitleaks.toml lists. Findings are redacted.
func secretScan() error {
	dir, err := repoDir()
	if err != nil {
		return err
	}
	for _, mode := range []string{"git", "dir"} {
		if err := run("docker", "run", "--rm", "-v", dir+":/repo", "-w", "/repo", gitleaksImage(),
			mode, "--redact", "--exit-code", "1", "--config", ".gitleaks.toml", "."); err != nil {
			return err
		}
	}
	return nil
}

// scanImage builds the server image and reports, with Trivy, HIGH and CRITICAL vulnerabilities that
// have a fix in its OS packages and binaries, and misconfigurations in the Dockerfile and compose
// files. The image is handed over as a saved tar, not the Docker socket.
func scanImage() error {
	dir, err := repoDir()
	if err != nil {
		return err
	}
	if err := run("docker", "build", "-q", "-t", scanImageTag(), "."); err != nil {
		return err
	}
	tar := filepath.Join("bin", "image-scan.tar")
	if err := os.MkdirAll("bin", 0o750); err != nil {
		return err
	}
	defer func() { _ = os.Remove(tar) }()
	if err := run("docker", "save", scanImageTag(), "-o", tar); err != nil {
		return err
	}
	trivy := []string{"run", "--rm", "-v", "qeet-id-trivy-cache:/root/.cache/trivy", "-v", dir + ":/repo", "-w", "/repo", trivyImage()}
	if err := run("docker", append(trivy, "image", "--input", "bin/image-scan.tar", "--exit-code", "1",
		"--severity", "HIGH,CRITICAL", "--ignore-unfixed", "--no-progress")...); err != nil {
		return err
	}
	return run("docker", append(trivy, "config", "--exit-code", "1", "--severity", "HIGH,CRITICAL", ".")...)
}

// ci is the full local gate before a push (CI runs only Verify).
func ci() error {
	if err := run("go", "build", "./..."); err != nil {
		return err
	}
	for _, step := range []func() error{testDB, lint, formatCheck, sqlcCheck, openapiCheck, vuln, sast, secretScan} {
		if err := step(); err != nil {
			return err
		}
	}
	fmt.Println("ci: every check passed")
	return nil
}

// sameFile reports whether a and b hold the same bytes.
func sameFile(a, b string) bool {
	x, errA := os.ReadFile(a) // #nosec G304 -- API documents this tool just built or the repository holds
	y, errB := os.ReadFile(b) // #nosec G304 -- as above
	return errA == nil && errB == nil && bytes.Equal(x, y)
}
