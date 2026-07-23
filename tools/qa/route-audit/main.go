// Command route-audit diffs every backend call-site in the console/login
// frontends against the OpenAPI route inventory, catching the bug class where a
// frontend calls a path the backend never registered — which no CI check covers
// (openapi_coverage_test.go only diffs the router against the spec).
//
//	go run ./tools/qa/route-audit                 # human-readable report on stdout
//	go run ./tools/qa/route-audit -md out.md      # markdown table, for qa/TESTING-FINDINGS.md
//
// It compares against the specs, not a live chi.Walk, because the coverage tests
// already prove the specs are in lockstep with the router — reusing them avoids
// importing the whole server. (The per-behavior parsing caveats — literal-only
// call sites, path-param normalization — are documented at their functions.)
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type route struct {
	method string
	path   string
}

type finding struct {
	route
	file string
	line int
}

// callPattern matches api(...)/api<T>(...) (console + login's shared shape)
// and apiGet/apiPost/apiPatch/apiDelete<T>(...) (login's per-verb shape).
// Only the call keyword + optional generic is matched here; the argument
// list itself is parsed by hand below since generics and template literals
// can both contain nested `<`/`>`/backtick characters a single regex can't
// safely balance.
var callPattern = regexp.MustCompile(`\bapi(Get|Post|Patch|Delete)?\s*(?:<)?`)

var methodOptPattern = regexp.MustCompile(`method:\s*["'](GET|POST|PATCH|PUT|DELETE)["']`)

var paramPattern = regexp.MustCompile(`\$\{[^}]*\}|\{[^}]*\}`)

func normalizeParams(p string) string {
	// Params first: a `${...}` interpolation can itself contain a literal
	// '?' (e.g. optional chaining, `${me.data?.id}`), so replacing the whole
	// interpolation before looking for a query-string '?' avoids truncating
	// mid-expression.
	p = paramPattern.ReplaceAllString(p, "{param}")
	// A few call sites bake a literal query string into the template
	// (e.g. `/v1/users?limit=200`) instead of using the api() helper's
	// separate `query` option — harmless at runtime (the backend only
	// matches the path portion before '?'), but it must be stripped here
	// or every such call falsely mismatches against the query-less spec key.
	if idx := strings.IndexByte(p, '?'); idx >= 0 {
		p = p[:idx]
	}
	if p != "/" {
		p = strings.TrimSuffix(p, "/")
	}
	return p
}

// skipGenerics advances past a balanced <...> generic argument list starting
// at i (where s[i] == '<'), returning the index just after the matching '>'.
func skipGenerics(s string, i int) int {
	depth := 0
	for ; i < len(s); i++ {
		switch s[i] {
		case '<':
			depth++
		case '>':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return i
}

// findMatchingParen returns the index of the ')' matching the '(' at s[open],
// skipping over nested (), {}, [], and string/template literals so a paren
// inside a string never confuses the depth count.
func findMatchingParen(s string, open int) int {
	depth := 0
	i := open
	for i < len(s) {
		c := s[i]
		switch c {
		case '(', '{', '[':
			depth++
		case ')', '}', ']':
			depth--
			if depth == 0 && c == ')' {
				return i
			}
		case '"', '\'', '`':
			i = skipStringLiteral(s, i)
			continue
		}
		i++
	}
	return len(s)
}

// skipStringLiteral advances past a quoted/template string starting at s[i]
// (s[i] is the opening quote char), honoring backslash escapes, and returns
// the index just after the closing quote.
func skipStringLiteral(s string, i int) int {
	quote := s[i]
	i++
	for i < len(s) {
		if s[i] == '\\' {
			i += 2
			continue
		}
		if s[i] == quote {
			return i + 1
		}
		i++
	}
	return i
}

// parseLeadingLiteral reads a string/template literal starting at s[i]
// (after skipping whitespace), returning its raw inner text (interpolations
// left as literal `${...}` substrings) and whether s[i] was in fact a
// literal at all (false for a bare identifier/expression argument).
func parseLeadingLiteral(s string, i int) (content string, ok bool) {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	if i >= len(s) || (s[i] != '"' && s[i] != '\'' && s[i] != '`') {
		return "", false
	}
	quote := s[i]
	start := i + 1
	end := skipStringLiteral(s, i) - 1 // index of closing quote
	if end < start || end > len(s) {
		return "", false
	}
	_ = quote
	return s[start:end], true
}

func scanFile(path string) []finding {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	s := string(raw)
	var out []finding

	for _, loc := range callPattern.FindAllStringSubmatchIndex(s, -1) {
		matchEnd := loc[1]
		verbGroupStart, verbGroupEnd := loc[2], loc[3]
		verb := ""
		if verbGroupStart >= 0 {
			verb = s[verbGroupStart:verbGroupEnd]
		}

		i := matchEnd
		// callPattern consumes a trailing '<' when present (part of the
		// match), so back up one to let skipGenerics re-find it cleanly.
		if i > 0 && s[i-1] == '<' {
			i = skipGenerics(s, i-1)
		}
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
			i++
		}
		if i >= len(s) || s[i] != '(' {
			continue // not actually a call (e.g. "apiary", "apiKey" false match)
		}
		closeParen := findMatchingParen(s, i)
		if closeParen >= len(s) {
			continue
		}
		argsText := s[i+1 : closeParen]

		pathLiteral, ok := parseLeadingLiteral(argsText, 0)
		if !ok || !strings.HasPrefix(pathLiteral, "/v1/") {
			continue // dynamic/non-literal first arg, or not our API — nothing to check
		}

		method := "GET"
		switch verb {
		case "Get":
			method = "GET"
		case "Post":
			method = "POST"
		case "Patch":
			method = "PATCH"
		case "Delete":
			method = "DELETE"
		case "":
			if m := methodOptPattern.FindStringSubmatch(argsText); m != nil {
				method = m[1]
			}
		}

		line := 1 + strings.Count(s[:loc[0]], "\n")
		out = append(out, finding{
			route: route{method: method, path: normalizeParams(pathLiteral)},
			file:  path,
			line:  line,
		})
	}
	return out
}

// specDoc/loadSpec/specRoutes deliberately mirror
// platform/api/rest/openapi_coverage_test.go's minimal parse — duplicated
// rather than imported since that file lives in a _test.go and this is a
// separate `go run` command, not a test binary.
type specDoc struct {
	OpenAPI string                                       `yaml:"openapi"`
	Paths   map[string]map[string]map[string]interface{} `yaml:"paths"`
}

func loadSpec(repoRoot string) (specDoc, error) {
	dir := filepath.Join(repoRoot, "api", "openapi")
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return specDoc{}, err
	}
	if len(files) == 0 {
		return specDoc{}, fmt.Errorf("no OpenAPI specs found under %s", dir)
	}
	merged := specDoc{Paths: map[string]map[string]map[string]interface{}{}}
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			return specDoc{}, err
		}
		var doc specDoc
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return specDoc{}, fmt.Errorf("parse %s: %w", path, err)
		}
		merged.OpenAPI = doc.OpenAPI
		for p, methods := range doc.Paths {
			merged.Paths[p] = methods
		}
	}
	return merged, nil
}

func specRoutes(doc specDoc) map[route]bool {
	out := map[route]bool{}
	for p, methods := range doc.Paths {
		norm := normalizeParams(p)
		for m := range methods {
			mu := strings.ToUpper(m)
			switch mu {
			case "GET", "POST", "PUT", "PATCH", "DELETE":
				out[route{method: mu, path: norm}] = true
			}
		}
	}
	return out
}

func walkTSFiles(root string) []string {
	var out []string
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.Contains(p, "node_modules") || strings.Contains(p, "routeTree.gen") {
			return nil
		}
		// The helper definition files themselves declare `api<T = unknown>(`
		// generics that look like call sites but aren't — skip them.
		if strings.HasSuffix(p, "/lib/api.ts") {
			return nil
		}
		if strings.HasSuffix(p, ".ts") || strings.HasSuffix(p, ".tsx") {
			out = append(out, p)
		}
		return nil
	})
	return out
}

func main() {
	mdOut := flag.String("md", "", "write a markdown table to this path instead of stdout text")
	flag.Parse()

	// `go run ./tools/qa/route-audit` (the only supported invocation, per
	// CLAUDE.md's "run from repo root" convention) runs with cwd == repo root.
	repoRoot := "."
	if _, err := os.Stat(filepath.Join(repoRoot, "go.mod")); err != nil {
		fmt.Fprintln(os.Stderr, "run this from the repo root: go run ./tools/qa/route-audit")
		os.Exit(1)
	}

	spec, err := loadSpec(repoRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load spec:", err)
		os.Exit(1)
	}
	specSet := specRoutes(spec)

	var findings []finding
	for _, app := range []string{"console", "login"} {
		root := filepath.Join(repoRoot, "apps", app, "src")
		if _, err := os.Stat(root); err != nil {
			continue
		}
		for _, f := range walkTSFiles(root) {
			findings = append(findings, scanFile(f)...)
		}
	}

	var mismatches []finding
	seen := map[string]bool{} // dedupe identical (method,path) across many call sites
	for _, f := range findings {
		if specSet[f.route] {
			continue
		}
		key := f.method + " " + f.path
		if seen[key] {
			continue
		}
		seen[key] = true
		mismatches = append(mismatches, f)
	}
	sort.Slice(mismatches, func(i, j int) bool {
		if mismatches[i].path != mismatches[j].path {
			return mismatches[i].path < mismatches[j].path
		}
		return mismatches[i].method < mismatches[j].method
	})

	fmt.Fprintf(os.Stderr, "scanned %d call sites, %d distinct (method,path) not found in api/openapi/*.yaml\n", len(findings), len(mismatches))

	if *mdOut != "" {
		var b strings.Builder
		b.WriteString("| Method | Path | First seen at |\n|---|---|---|\n")
		for _, m := range mismatches {
			rel := strings.TrimPrefix(m.file, repoRoot+string(filepath.Separator))
			fmt.Fprintf(&b, "| %s | `%s` | `%s:%d` |\n", m.method, m.path, rel, m.line)
		}
		if err := os.WriteFile(*mdOut, []byte(b.String()), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "write md:", err)
			os.Exit(1)
		}
		return
	}

	for _, m := range mismatches {
		rel := strings.TrimPrefix(m.file, repoRoot+string(filepath.Separator))
		fmt.Printf("%-7s %-55s %s:%d\n", m.method, m.path, rel, m.line)
	}
	if len(mismatches) > 0 {
		os.Exit(1)
	}
}
