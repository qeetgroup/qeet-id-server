package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// The pinned dynamic scanners; ZAP_IMAGE and SCHEMATHESIS_IMAGE override them.
func zapImage() string {
	return envOr("ZAP_IMAGE", "zaproxy/zap-stable:2.17.0@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af")
}

func schemathesisImage() string {
	return envOr("SCHEMATHESIS_IMAGE", "schemathesis/schemathesis:4.33.0@sha256:57cdf625c01901bc050355225251a7fc255c0cd8a07d4ac77fb86e4d3ffb25a2")
}

// scanTarget is what the dynamic scans run against: a running local server (SCAN_BASE_URL, by default
// this machine's HTTP_PORT as Docker reaches it), the documents named in SCAN_DOCS (default all five),
// and the optional bearer token SCAN_TOKEN, so signed-in routes are reached too.
type scanTarget struct {
	repo, reports, base, token string
	docs                       []string
}

func newScanTarget(tool string) (scanTarget, error) {
	repo, err := repoDir()
	if err != nil {
		return scanTarget{}, err
	}
	t := scanTarget{
		repo: repo, reports: filepath.Join(repo, "bin", "reports", tool),
		base:  envOr("SCAN_BASE_URL", "http://host.docker.internal:"+envOr("HTTP_PORT", "4001")),
		token: os.Getenv("SCAN_TOKEN"),
	}
	// Only the five documents, named from the fixed list: SCAN_DOCS chooses, it never names a path.
	for _, want := range strings.Fields(strings.ReplaceAll(envOr("SCAN_DOCS", strings.Join(openapiDocs, " ")), ",", " ")) {
		i := slices.Index(openapiDocs, want)
		if i < 0 {
			return scanTarget{}, fmt.Errorf("SCAN_DOCS: no API document %q (the documents: %s)", want, strings.Join(openapiDocs, " "))
		}
		t.docs = append(t.docs, openapiDocs[i])
	}
	fmt.Printf("%s: scanning %s with %s. It sends attacks and changes data: point it at a throwaway server.\n",
		tool, t.base, strings.Join(t.docs, " "))
	return t, os.MkdirAll(t.reports, 0o750)
}

// servers matches a document's servers block, which the scan copy points at the target instead.
var servers = regexp.MustCompile(`(?m)^servers:\n(?:[ -].*\n)*`)

// dast runs OWASP ZAP's API scan over each document against the target, with HTML and JSON reports
// in bin/reports/zap. It fails on a FAIL-level alert; WARN-level ones are reported only.
func dast() error {
	t, err := newScanTarget("zap")
	if err != nil {
		return err
	}
	for _, doc := range t.docs {
		raw, err := os.ReadFile(filepath.Join(t.repo, "api", "openapi", doc+".yaml")) // #nosec G304 -- the repository's own documents
		if err != nil {
			return err
		}
		local := servers.ReplaceAll(raw, []byte("servers:\n  - url: "+t.base+"\n"))
		// #nosec G703 -- doc is taken from the fixed document list (newScanTarget), never from SCAN_DOCS' text
		if err := os.WriteFile(filepath.Join(t.reports, doc+".yaml"), local, 0o600); err != nil {
			return err
		}
		args := []string{"run", "--rm", "--add-host=host.docker.internal:host-gateway", "-v", t.reports + ":/zap/wrk:rw",
			zapImage(), "zap-api-scan.py", "-t", doc + ".yaml", "-f", "openapi", "-r", doc + ".html", "-J", doc + ".json"}
		if t.token != "" {
			args = append(args, "-z", "-config replacer.full_list(0).description=auth -config replacer.full_list(0).enabled=true "+
				"-config replacer.full_list(0).matchtype=REQ_HEADER -config replacer.full_list(0).matchstr=Authorization "+
				"-config replacer.full_list(0).regex=false -config replacer.full_list(0).replacement=Bearer "+t.token)
		}
		// zap-api-scan exits 1 with a FAIL alert, 2 with warnings only, 3 when it couldn't run.
		if code := exitCode(run("docker", args...)); code == 1 || code > 2 {
			return fmt.Errorf("zap: %s: exit %d; see bin/reports/zap/%s.html", doc, code, doc)
		}
	}
	fmt.Println("dast: reports in bin/reports/zap/")
	return nil
}

// fuzzAPI runs Schemathesis over each document against the target: generated requests for every
// operation, the checks schemathesis.toml selects (no 5xx, answers as documented), at SCAN_RATE,
// with JUnit and HAR reports in bin/reports/schemathesis. SCAN_EXAMPLES sets the examples per operation.
func fuzzAPI() error {
	t, err := newScanTarget("schemathesis")
	if err != nil {
		return err
	}
	var failed []string
	for _, doc := range t.docs {
		args := []string{"run", "--rm", "--add-host=host.docker.internal:host-gateway",
			"-v", filepath.Join(t.repo, "api", "openapi") + ":/docs:ro", "-v", t.reports + ":/reports:rw",
			"-v", filepath.Join(t.repo, "schemathesis.toml") + ":/config/schemathesis.toml:ro",
			schemathesisImage(), "--config-file", "/config/schemathesis.toml",
			"run", "/docs/" + doc + ".yaml", "--url", t.base, "--rate-limit", envOr("SCAN_RATE", "10/s"),
			"--max-examples", envOr("SCAN_EXAMPLES", "10"), "--report", "junit,har",
			"--report-junit-path", "/reports/" + doc + ".junit.xml", "--report-har-path", "/reports/" + doc + ".har"}
		if t.token != "" {
			args = append(args, "-H", "Authorization: Bearer "+t.token)
		}
		if err := run("docker", args...); err != nil {
			failed = append(failed, doc)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("schemathesis found failures in %s; see bin/reports/schemathesis/", strings.Join(failed, " "))
	}
	fmt.Println("fuzz-api: no failures; reports in bin/reports/schemathesis/")
	return nil
}

// exitCode is err's process exit code: 0 for nil, -1 when the command didn't run.
func exitCode(err error) int {
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exit):
		return exit.ExitCode()
	default:
		return -1
	}
}
