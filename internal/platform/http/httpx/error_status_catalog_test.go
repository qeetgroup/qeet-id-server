package httpx

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// repoRoot is the module root, relative to this package's directory.
var repoRoot = filepath.Join("..", "..", "..", "..")

// adHocCodes lists the functions allowed to build an error code outside the
// errs catalogue, keyed "path#Func"; every other errs.New call must pass an
// errs.Code* constant. Delete an entry once its codes move into the catalogue.
var adHocCodes = map[string]string{}

// TestEveryCatalogCodeHasStatus checks that each errs.Code* constant maps to an
// HTTP status. An unmapped code would silently fall back to 400.
func TestEveryCatalogCodeHasStatus(t *testing.T) {
	codes := catalogCodes(t)
	if len(codes) < 100 {
		t.Fatalf("found only %d errs.Code* constants; the parser is probably broken", len(codes))
	}
	for name, code := range codes {
		if _, ok := statusByCode[code]; !ok {
			t.Errorf("errs.%s (%q) has no HTTP status: add it to statusByCode or the domain's error_status_*.go", name, code)
		}
	}
}

// TestErrorCodesComeFromTheCatalog checks that errs.New is called with an
// errs.Code* constant outside the errs package, so every code has a status.
func TestErrorCodesComeFromTheCatalog(t *testing.T) {
	seen := map[string]bool{}
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(repoRoot, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(repoRoot, path)
			rel = filepath.ToSlash(rel)
			if d.IsDir() {
				if d.Name() == "dbgen" || rel == "internal/platform/http/errs" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
				return nil
			}
			for _, fn := range adHocCallers(t, path) {
				key := rel + "#" + fn
				seen[key] = true
				if _, ok := adHocCodes[key]; !ok {
					t.Errorf("%s builds an error code outside the errs catalogue: add an errs.Code* constant and its status instead", key)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for key := range adHocCodes {
		if !seen[key] {
			t.Errorf("adHocCodes entry %s matches no ad-hoc errs.New call: delete it", key)
		}
	}
}

// TestAdHocCallersFindsLiteralCodes checks that adHocCallers flags an errs.New
// call with a literal code and ignores one with an errs.Code* constant.
func TestAdHocCallersFindsLiteralCodes(t *testing.T) {
	src := `package p

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

type S struct{}

func (S) Bad() error  { return errs.New("adhoc_code", "x") }
func Good() error     { return errs.New(errs.CodeConflict, "x") }
`
	path := filepath.Join(t.TempDir(), "p.go")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := adHocCallers(t, path); len(got) != 1 || got[0] != "S.Bad" {
		t.Fatalf("adHocCallers = %v, want [S.Bad]", got)
	}
}

// catalogCodes returns the errs.Code* string constants, by name.
func catalogCodes(t *testing.T) map[string]string {
	t.Helper()
	dir := filepath.Join(repoRoot, "internal", "platform", "http", "errs")
	matches, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	codes := map[string]string{}
	fset := token.NewFileSet()
	for _, path := range matches {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, name := range vs.Names {
					if !strings.HasPrefix(name.Name, "Code") || i >= len(vs.Values) {
						continue
					}
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if v, err := strconv.Unquote(lit.Value); err == nil {
							codes[name.Name] = v
						}
					}
				}
			}
		}
	}
	return codes
}

// adHocCallers returns the functions in path that call errs.New with anything
// other than an errs.Code* constant, named Func or Recv.Method.
func adHocCallers(t *testing.T, path string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	alias := ""
	for _, imp := range f.Imports {
		if strings.Trim(imp.Path.Value, `"`) == "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs" {
			alias = "errs"
			if imp.Name != nil {
				alias = imp.Name.Name
			}
		}
	}
	if alias == "" {
		return nil
	}
	var out []string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		found := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || found || !isSelector(call.Fun, alias, "New") || len(call.Args) == 0 {
				return true
			}
			if sel, ok := call.Args[0].(*ast.SelectorExpr); ok && isSelector(sel, alias, sel.Sel.Name) && strings.HasPrefix(sel.Sel.Name, "Code") {
				return true
			}
			found = true
			return false
		})
		if found {
			out = append(out, funcName(fn))
		}
	}
	return out
}

func isSelector(e ast.Expr, pkg, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg
}

func funcName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	typ := fn.Recv.List[0].Type
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	if id, ok := typ.(*ast.Ident); ok {
		return id.Name + "." + fn.Name.Name
	}
	return fn.Name.Name
}
