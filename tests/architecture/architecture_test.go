// Package architecture checks the repository's layout rules (AGENTS.md, "Tests") over every Go
// file: names a newcomer can rely on. Import direction is depguard's job (.golangci.yml), SQL
// scoping organizationguard's and txguard's.
package architecture

import (
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const module = "github.com/qeetgroup/qeet-id-server/"

// goFile is one parsed Go file, its path relative to the repository root.
type goFile struct {
	rel  string
	dir  string
	ast  *ast.File
	test bool
}

// repoFiles parses the imports and header comments of every Go file in the repository.
func repoFiles(t *testing.T) []goFile {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root not found from %s: %v", root, err)
	}
	var files []goFile
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && (strings.HasPrefix(d.Name(), ".") || slices.Contains([]string{"node_modules", "bin", "testdata", "vendor"}, d.Name())) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly|parser.ParseComments)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		files = append(files, goFile{rel: rel, dir: path.Dir(rel), ast: f, test: strings.HasSuffix(rel, "_test.go")})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// report fails t with every violation, one per line, then how to fix them.
func report(t *testing.T, violations []string, fix string) {
	t.Helper()
	if len(violations) > 0 {
		t.Errorf("%d found:\n  %s\n%s", len(violations), strings.Join(violations, "\n  "), fix)
	}
}

// A package is named for its directory, so an import path tells you the name it is used by.
func TestDirectoryIsThePackageName(t *testing.T) {
	var bad []string
	for _, f := range repoFiles(t) {
		name := strings.TrimSuffix(f.ast.Name.Name, "_test")
		if name != "main" && name != path.Base(f.dir) {
			bad = append(bad, f.rel+": package "+f.ast.Name.Name)
		}
	}
	report(t, bad, "Rename the directory to the package name (or the package to the directory's).")
}

// An internal package is imported under its own name; an alias is allowed only where that name
// would clash: with another import in the file, or with the importer's own package of that name
// (another context's dbgen, in a package that has its own).
func TestInternalImportsKeepTheirName(t *testing.T) {
	files := repoFiles(t)
	dirs := map[string]bool{}
	for _, f := range files {
		dirs[f.dir] = true
	}
	var bad []string
	for _, f := range files {
		names := map[string]int{}
		for _, im := range f.ast.Imports {
			names[path.Base(strings.Trim(im.Path.Value, `"`))]++
		}
		for _, im := range f.ast.Imports {
			p := strings.Trim(im.Path.Value, `"`)
			if im.Name == nil || im.Name.Name == "_" || !strings.HasPrefix(p, module) {
				continue
			}
			own := path.Join(f.dir, path.Base(p))
			clash := names[path.Base(p)] > 1 || (dirs[own] && strings.TrimPrefix(p, module) != own)
			if im.Name.Name == "." || !clash {
				bad = append(bad, f.rel+": "+im.Name.Name+" "+strings.TrimPrefix(p, module))
			}
		}
	}
	report(t, bad, "Drop the alias: use the package's own name.")
}

// A test file is named after the code file it tests (foo_test.go, foo_db_test.go beside foo.go),
// or after its package for whole-package tests and helpers, or is deps_test.go, the test doubles
// its package's constructors take. Packages with no code (tests/, the SQL guards) and
// internal/bootstrap's whole-server checks name theirs for what they check.
func TestTestFilesAreNamedForTheirCode(t *testing.T) {
	files := repoFiles(t)
	code := map[string]bool{}
	hasCode := map[string]bool{}
	for _, f := range files {
		if !f.test {
			code[f.rel] = true
			hasCode[f.dir] = true
		}
	}
	var bad []string
	for _, f := range files {
		if !f.test || !hasCode[f.dir] || f.dir == "internal/bootstrap" {
			continue
		}
		base := strings.TrimSuffix(strings.TrimSuffix(path.Base(f.rel), "_test.go"), "_db")
		if code[path.Join(f.dir, base+".go")] || base == path.Base(f.dir) || base == "deps" {
			continue
		}
		bad = append(bad, f.rel)
	}
	report(t, bad, "Name the file after the code file it tests, or move its tests into that file's tests.")
}

// A test that needs PostgreSQL is named *_db_test.go and builds only with -tags integration, so
// go test ./... runs without a database; no other test file carries the tag.
func TestDatabaseTestsAreTaggedIntegration(t *testing.T) {
	var bad []string
	for _, f := range repoFiles(t) {
		if !f.test {
			continue
		}
		db, tagged := strings.HasSuffix(f.rel, "_db_test.go"), needsIntegrationTag(f.ast)
		switch {
		case db && !tagged:
			bad = append(bad, f.rel+": needs //go:build integration as its first line")
		case !db && tagged:
			bad = append(bad, f.rel+": tagged integration, so name it *_db_test.go (or drop the tag)")
		}
	}
	report(t, bad, "A database test is foo_db_test.go with //go:build integration; any other test runs without it.")
}

// Test folders are not nested in packages: tests that span the server live in tests/ at the root.
func TestNoNestedTestFolders(t *testing.T) {
	var bad []string
	seen := map[string]bool{}
	for _, f := range repoFiles(t) {
		for dir := f.dir; dir != "." && !seen[dir]; dir = path.Dir(dir) {
			seen[dir] = true
			if b := path.Base(dir); (b == "test" || b == "tests") && dir != "tests" {
				bad = append(bad, dir)
			}
		}
	}
	report(t, bad, "Put a package's tests beside its code, or a whole-server test under tests/.")
}

// needsIntegrationTag reports whether the file's build constraint holds only with the integration tag.
func needsIntegrationTag(f *ast.File) bool {
	for _, group := range f.Comments {
		if group.Pos() >= f.Package {
			break
		}
		for _, c := range group.List {
			if !constraint.IsGoBuild(c.Text) {
				continue
			}
			expr, err := constraint.Parse(c.Text)
			if err != nil {
				return false
			}
			return expr.Eval(func(tag string) bool { return tag == "integration" }) && !expr.Eval(func(string) bool { return false })
		}
	}
	return false
}
