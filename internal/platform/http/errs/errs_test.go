package errs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestNewRefusesACodeDeclaredTwice checks that declaring a code a second time
// panics, so two errors can never answer with one code.
func TestNewRefusesACodeDeclaredTwice(t *testing.T) {
	New("errs_test.once", KindConflict, "first")
	defer func() {
		if r := recover(); r == nil || !strings.Contains(r.(string), "errs_test.once") {
			t.Errorf("a code declared twice: recovered %v, want a panic naming it", r)
		}
	}()
	New("errs_test.once", KindConflict, "second")
}

// TestLookup checks that a declared error is found by its code, with its kind,
// and that an unknown code isn't.
func TestLookup(t *testing.T) {
	declared := New("errs_test.lookup", KindGone, "gone")
	if e, ok := Lookup("errs_test.lookup"); !ok || e != declared || e.Kind != KindGone {
		t.Errorf("Lookup of a declared code = %+v, %v", e, ok)
	}
	if e, ok := Lookup("errs_test.never"); ok || e != nil {
		t.Errorf("Lookup of an unknown code = %+v, %v", e, ok)
	}
}

// TestCopiesKeepTheKind checks that an error changed for one answer keeps its
// kind, so it is answered with the same status.
func TestCopiesKeepTheKind(t *testing.T) {
	e := New("errs_test.copies", KindTooManyRequests, "slow down")
	for name, c := range map[string]*Error{
		"AsRetryable": e.AsRetryable(), "WithDetail": e.WithDetail("d"), "WithMessage": e.WithMessage("m"),
		"WithMetadata": e.WithMetadata(map[string]any{"k": 1}), "Wrap": e.Wrap(errString("cause")),
		"WithFields": e.WithFields(nil), "WithTranslationKey": e.WithTranslationKey("k"),
	} {
		if c.Kind != KindTooManyRequests || c.Code != e.Code {
			t.Errorf("%s: kind %v, code %s", name, c.Kind, c.Code)
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// repoRoot is the module root, relative to this package's directory.
var repoRoot = filepath.Join("..", "..", "..", "..")

// TestEveryErrorIsDeclaredOnce checks every errs.New call in the module: it
// declares a package-level var, with a code written as a string literal (or a
// constant holding one) and an errs.Kind, and no code is declared twice. A call
// inside a function would declare its code again on every run, and panic.
func TestEveryErrorIsDeclaredOnce(t *testing.T) {
	seen := map[string]string{}
	calls := 0
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(repoRoot, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}
			rel, _ := filepath.Rel(repoRoot, path)
			rel = filepath.ToSlash(rel)
			inErrs := strings.HasPrefix(rel, "internal/platform/http/errs/")
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			consts := map[string]string{}
			for _, decl := range f.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}
				for _, s := range gd.Specs {
					vs := s.(*ast.ValueSpec)
					for i, n := range vs.Names {
						if i < len(vs.Values) {
							if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
								consts[n.Name], _ = strconv.Unquote(lit.Value)
							}
						}
					}
				}
			}
			isNew := func(call *ast.CallExpr) bool {
				switch fn := call.Fun.(type) {
				case *ast.SelectorExpr:
					x, ok := fn.X.(*ast.Ident)
					return ok && x.Name == "errs" && fn.Sel.Name == "New"
				case *ast.Ident:
					return inErrs && fn.Name == "New"
				}
				return false
			}
			atTop := map[*ast.CallExpr]bool{}
			for _, decl := range f.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.VAR {
					continue
				}
				for _, s := range gd.Specs {
					for _, v := range s.(*ast.ValueSpec).Values {
						ast.Inspect(v, func(n ast.Node) bool {
							if call, ok := n.(*ast.CallExpr); ok && isNew(call) {
								atTop[call] = true
							}
							return true
						})
					}
				}
			}
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || !isNew(call) {
					return true
				}
				calls++
				if !atTop[call] && (!inErrs || !strings.HasSuffix(rel, "_test.go")) {
					t.Errorf("%s: errs.New inside a function; declare the error in a package-level var", rel)
					return true
				}
				if len(call.Args) != 3 {
					t.Errorf("%s: errs.New with %d arguments", rel, len(call.Args))
					return true
				}
				code := ""
				switch a := call.Args[0].(type) {
				case *ast.BasicLit:
					code, _ = strconv.Unquote(a.Value)
				case *ast.Ident:
					code = consts[a.Name]
				}
				if code == "" {
					t.Errorf("%s: an error code that isn't a string literal or a constant holding one", rel)
				}
				kind := ""
				switch k := call.Args[1].(type) {
				case *ast.SelectorExpr:
					kind = k.Sel.Name
				case *ast.Ident:
					kind = k.Name
				}
				if !strings.HasPrefix(kind, "Kind") {
					t.Errorf("%s: %s declared without an errs.Kind", rel, code)
				}
				if strings.HasSuffix(rel, "_test.go") {
					return true // a test's own errors only need to be unique within it
				}
				if code != "" {
					if other, dup := seen[code]; dup {
						t.Errorf("%s: %s is already declared in %s", rel, code, other)
					}
					seen[code] = rel
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) < 300 {
		t.Fatalf("found only %d declared codes in %d calls; the walk is probably broken", len(seen), calls)
	}
}
