// Package txguard_test fails when a function holds a pgx transaction and,
// before it ends, uses the connection pool directly or through a helper in
// the same package. The transaction pins one connection, so each such call
// needs a second one. The scan is syntactic: calls into other packages,
// through interfaces or through function values are not followed.
package txguard_test

import (
	"bufio"
	"cmp"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const (
	allowlistPath = "internal/platform/database/txguard/allowlist_test.go"
	scanDir       = "internal"
	pgxPath       = "github.com/jackc/pgx/v5"
	pgxpoolPath   = "github.com/jackc/pgx/v5/pgxpool"
)

// categories are the accepted reasons for a function to be allowlisted.
var categories = map[string]bool{
	"pending-fix":      true,
	"after-commit":     true,
	"separate-concern": true,
}

// poolMethods are the *pgxpool.Pool methods that take a connection.
var poolMethods = map[string]bool{
	"Acquire": true, "AcquireFunc": true, "Begin": true, "BeginTx": true, "CopyFrom": true,
	"Exec": true, "Ping": true, "Query": true, "QueryRow": true, "SendBatch": true,
}

func TestNoPoolInTransaction(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	pkgs := parse(t, fset, root)
	names := collectNames(pkgs)
	var fns []*fn
	for _, p := range pkgs {
		fns = append(fns, p.scan(names)...)
	}
	resolve(fns)
	holders := 0
	for _, f := range fns {
		if len(f.events) > 0 {
			holders++
		}
	}
	if holders == 0 || len(names.fields) == 0 || len(names.queriers) == 0 {
		t.Fatalf("found %d functions holding a transaction, %d pool fields and %d querier fields; the scanner is broken",
			holders, len(names.fields), len(names.queriers))
	}
	allow := readAllowlist(t, root)
	for _, problem := range check(fset, fns, allow) {
		t.Error(problem)
	}
	t.Logf("scanned %d functions, %d holding a transaction; %d allowlisted", len(fns), holders, len(allow))
}

// check returns one message per function that uses the pool inside a
// transaction and is not allowlisted, and per stale allowlist entry. allow
// maps each key to its line number.
func check(fset *token.FileSet, fns []*fn, allow map[string]int) []string {
	var problems []string
	found, flagged := map[string]bool{}, map[string]bool{}
	for _, f := range fns {
		found[f.key] = true
		sites := f.inTx()
		if len(sites) == 0 {
			continue
		}
		flagged[f.key] = true
		if _, ok := allow[f.key]; ok {
			continue
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%s: %s uses the connection pool while it holds a transaction:", at(fset, f.decl.Pos()), f.name)
		for _, s := range sites {
			fmt.Fprintf(&b, "\n\t%s: %s", at(fset, s.pos), s.describe(fset))
		}
		fmt.Fprintf(&b, "\n\tRun the query on the transaction instead: pass tx, or q.WithTx(tx), to the helper,\n"+
			"\tor move the call after Commit. If it must stay outside the transaction, add this line to\n"+
			"\t%s (categories are listed at the top of the file):\n"+
			"\t%s  <category>: <reason>", allowlistPath, f.key)
		problems = append(problems, b.String())
	}
	for key, line := range allow {
		switch {
		case !found[key]:
			problems = append(problems, fmt.Sprintf(
				"%s:%d: %s matches no function (renamed or removed?); delete the line.", allowlistPath, line, key))
		case !flagged[key]:
			problems = append(problems, fmt.Sprintf(
				"%s:%d: %s no longer uses the pool inside a transaction; delete the line.", allowlistPath, line, key))
		}
	}
	sort.Strings(problems)
	return problems
}

// file is one parsed Go file.
type file struct {
	rel          string
	ast          *ast.File
	pgx, pgxpool string // local names of those imports, or ""
}

// pkg is the scanned files of one directory.
type pkg struct {
	files  []*file
	fields map[string]map[string]string // struct type -> field -> same-package type
	embeds map[string][]string          // struct type -> embedded same-package types
	funcs  map[string]*fn               // Name or Recv.Name
}

// fn is one function declaration and what the scan found in its body,
// including the function literals inside it.
type fn struct {
	key     string // path#Name or path#Recv.Name, the allowlist key
	name    string // Name or Recv.Name
	decl    *ast.FuncDecl
	takesTx bool    // has a pgx.Tx parameter, so it is checked on its own
	events  []event // where transactions open and close
	uses    []site  // direct pool use anywhere in the body
	calls   []site  // calls to functions of the same package
	via     *site   // how a call to fn reaches the pool, or nil
}

// site is a pool use, or a call to a function that leads to one.
type site struct {
	pos    token.Pos
	what   string
	callee *fn
}

// event opens or closes transaction tx from start to the end of the
// enclosing block.
type event struct {
	tx         string
	open       bool
	start, end token.Pos
}

// names are the identifiers that reach the pool, from declarations anywhere
// in the scan.
type names struct {
	fields   map[string]bool // struct fields of type *pgxpool.Pool
	queriers map[string]bool // struct fields of type *<pkg>.Queries, built from the pool
	getters  map[string]bool // methods that return *pgxpool.Pool
}

// kind is what an expression holds.
type kind int

const (
	other kind = iota
	pool
	querier
)

// parse returns the non-test, non-generated Go files under scanDir, one pkg
// per directory.
func parse(t *testing.T, fset *token.FileSet, root string) []*pkg {
	t.Helper()
	byDir := map[string]*pkg{}
	var out []*pkg
	walk(t, root, filepath.Join(root, scanDir), func(path, rel string) {
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return
		}
		f, err := parser.ParseFile(fset, rel, readFile(t, path), parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		if ast.IsGenerated(f) {
			return
		}
		pf := &file{rel: rel, ast: f}
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			name := ""
			if imp.Name != nil {
				name = imp.Name.Name
			}
			switch path {
			case pgxPath:
				pf.pgx = cmp.Or(name, "pgx")
			case pgxpoolPath:
				pf.pgxpool = cmp.Or(name, "pgxpool")
			}
		}
		dir := filepath.Dir(rel)
		p := byDir[dir]
		if p == nil {
			p = &pkg{fields: map[string]map[string]string{}, embeds: map[string][]string{}, funcs: map[string]*fn{}}
			byDir[dir] = p
			out = append(out, p)
		}
		p.files = append(p.files, pf)
	})
	return out
}

// collectNames finds the pool and querier fields and the pool getters.
func collectNames(pkgs []*pkg) names {
	n := names{fields: map[string]bool{}, queriers: map[string]bool{}, getters: map[string]bool{}}
	for _, p := range pkgs {
		for _, f := range p.files {
			ast.Inspect(f.ast, func(node ast.Node) bool {
				switch x := node.(type) {
				case *ast.StructType:
					for _, fld := range x.Fields.List {
						for _, name := range fld.Names {
							switch {
							case f.isPool(fld.Type):
								n.fields[name.Name] = true
							case isQuerier(fld.Type):
								n.queriers[name.Name] = true
							}
						}
					}
				case *ast.InterfaceType:
					for _, m := range x.Methods.List {
						if ft, ok := m.Type.(*ast.FuncType); ok && f.returnsPool(ft) {
							for _, name := range m.Names {
								n.getters[name.Name] = true
							}
						}
					}
				case *ast.FuncDecl:
					if x.Recv != nil && f.returnsPool(x.Type) {
						n.getters[x.Name.Name] = true
					}
				}
				return true
			})
		}
	}
	return n
}

// scan indexes the package and records the transactions, pool uses and
// same-package calls of each function.
func (p *pkg) scan(n names) []*fn {
	type decl struct {
		fn   *fn
		file *file
	}
	var decls []decl
	for _, f := range p.files {
		for _, d := range f.ast.Decls {
			switch d := d.(type) {
			case *ast.GenDecl:
				p.indexTypes(d)
			case *ast.FuncDecl:
				if d.Body == nil {
					continue
				}
				x := &fn{key: f.rel + "#" + funcName(d), name: funcName(d), decl: d}
				if _, dup := p.funcs[x.name]; !dup {
					p.funcs[x.name] = x
				}
				decls = append(decls, decl{x, f})
			}
		}
	}
	out := make([]*fn, 0, len(decls))
	for _, d := range decls {
		p.scanFunc(d.fn, d.file, n)
		out = append(out, d.fn)
	}
	return out
}

// indexTypes records the same-package field types of each struct.
func (p *pkg) indexTypes(gen *ast.GenDecl) {
	for _, spec := range gen.Specs {
		ts, ok := spec.(*ast.TypeSpec)
		if !ok {
			continue
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			continue
		}
		fields := map[string]string{}
		for _, fld := range st.Fields.List {
			typ := localType(fld.Type)
			if typ == "" {
				continue
			}
			if len(fld.Names) == 0 {
				p.embeds[ts.Name.Name] = append(p.embeds[ts.Name.Name], typ)
				fields[typ] = typ
			}
			for _, name := range fld.Names {
				fields[name.Name] = typ
			}
		}
		p.fields[ts.Name.Name] = fields
	}
}

// scanFunc fills in f.events, f.uses and f.calls. A go statement is skipped,
// since the transaction does not wait for it.
func (p *pkg) scanFunc(f *fn, file *file, n names) {
	recv, recvType := receiver(f.decl)
	locals := n.locals(f.decl, file)
	txs := map[string]bool{}
	openParams := func(ft *ast.FuncType, body *ast.BlockStmt) {
		for _, fld := range ft.Params.List {
			if !file.isTx(fld.Type) {
				continue
			}
			for _, name := range paramNames(fld) {
				txs[name] = true
				f.events = append(f.events, event{tx: name, open: true, start: body.Lbrace, end: body.Rbrace})
			}
		}
	}
	openParams(f.decl.Type, f.decl.Body)
	f.takesTx = len(f.events) > 0
	var stack []ast.Node
	ast.Inspect(f.decl.Body, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		switch x := node.(type) {
		case *ast.GoStmt:
			return false
		case *ast.FuncLit:
			openParams(x.Type, x.Body)
		case *ast.AssignStmt:
			if name := beginsTx(x); name != "" {
				txs[name] = true
				f.events = append(f.events, event{tx: name, open: true, start: x.End(), end: blockEnd(stack)})
			}
		case *ast.CallExpr:
			sel, _ := x.Fun.(*ast.SelectorExpr)
			if sel != nil {
				method := sel.Sel.Name
				switch k := n.kind(sel.X, locals); {
				case k == pool && poolMethods[method], k == querier && method != "WithTx":
					f.uses = append(f.uses, site{pos: x.Pos(), what: types.ExprString(x.Fun)})
				}
				if id, ok := sel.X.(*ast.Ident); ok && txs[id.Name] && (method == "Commit" || method == "Rollback") && !deferred(stack) {
					f.events = append(f.events, event{tx: id.Name, start: x.Pos(), end: blockEnd(stack)})
				}
			}
			if n.kind(x, locals) == other && (sel == nil || sel.Sel.Name != "WithTx") {
				for _, arg := range x.Args {
					if n.kind(arg, locals) != other {
						f.uses = append(f.uses, site{pos: arg.Pos(), what: "passes " + types.ExprString(arg) + " to " + types.ExprString(x.Fun)})
					}
				}
			}
			if callee := p.callee(x.Fun, recv, recvType); callee != nil && callee != f {
				f.calls = append(f.calls, site{pos: x.Pos(), what: types.ExprString(x.Fun), callee: callee})
			}
		}
		stack = append(stack, node)
		return true
	})
}

// callee returns the same-package function or method that fun names: F,
// recv.M or recv.field.M. It returns nil for anything else.
func (p *pkg) callee(fun ast.Expr, recv, recvType string) *fn {
	switch fun := fun.(type) {
	case *ast.Ident:
		return p.funcs[fun.Name]
	case *ast.IndexExpr:
		return p.callee(fun.X, recv, recvType)
	case *ast.SelectorExpr:
		if recv == "" {
			return nil
		}
		switch x := fun.X.(type) {
		case *ast.Ident:
			if x.Name == recv {
				return p.method(recvType, fun.Sel.Name, 0)
			}
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && id.Name == recv {
				if typ := p.field(recvType, x.Sel.Name, 0); typ != "" {
					return p.method(typ, fun.Sel.Name, 0)
				}
			}
		}
	}
	return nil
}

// method returns method m of typ, looking through embedded fields.
func (p *pkg) method(typ, m string, depth int) *fn {
	if f := p.funcs[typ+"."+m]; f != nil || depth > 2 {
		return f
	}
	for _, e := range p.embeds[typ] {
		if f := p.method(e, m, depth+1); f != nil {
			return f
		}
	}
	return nil
}

// field returns the same-package type of field name of typ, looking through
// embedded fields.
func (p *pkg) field(typ, name string, depth int) string {
	if t, ok := p.fields[typ][name]; ok || depth > 2 {
		return t
	}
	for _, e := range p.embeds[typ] {
		if t := p.field(e, name, depth+1); t != "" {
			return t
		}
	}
	return ""
}

// resolve sets via on every function that reaches the pool, directly or
// through same-package calls. A function that takes a pgx.Tx is checked on
// its own, so it is not blamed on its callers.
func resolve(fns []*fn) {
	for _, f := range fns {
		if !f.takesTx && len(f.uses) > 0 {
			f.via = &f.uses[0]
		}
	}
	for changed := true; changed; {
		changed = false
		for _, f := range fns {
			if f.via != nil || f.takesTx {
				continue
			}
			for i := range f.calls {
				if f.calls[i].callee.via != nil {
					f.via = &f.calls[i]
					changed = true
					break
				}
			}
		}
	}
}

// inTx returns the pool uses, and the calls that reach the pool, made while
// f holds a transaction.
func (f *fn) inTx() []site {
	var out []site
	for _, s := range f.uses {
		if f.holding(s.pos) {
			out = append(out, s)
		}
	}
	for _, c := range f.calls {
		if c.callee.via != nil && f.holding(c.pos) {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].pos < out[j].pos })
	return out
}

// holding reports whether, for some transaction, the latest event in scope
// before pos opened it.
func (f *fn) holding(pos token.Pos) bool {
	latest := map[string]event{}
	for _, e := range f.events {
		if prev, ok := latest[e.tx]; e.start < pos && pos < e.end && (!ok || e.start > prev.start) {
			latest[e.tx] = e
		}
	}
	for _, e := range latest {
		if e.open {
			return true
		}
	}
	return false
}

// describe renders a site, following a call down to the pool use it reaches.
func (s site) describe(fset *token.FileSet) string {
	if s.callee == nil {
		return s.what
	}
	parts := []string{s.what}
	cur := s
	for cur.callee != nil {
		cur = *cur.callee.via
		parts = append(parts, cur.what)
	}
	return strings.Join(parts, " -> ") + " (" + at(fset, cur.pos) + ")"
}

// kind reports whether e holds the pool, a pool-bound querier, or neither.
func (n names) kind(e ast.Expr, locals map[string]kind) kind {
	switch e := e.(type) {
	case *ast.ParenExpr:
		return n.kind(e.X, locals)
	case *ast.Ident:
		return locals[e.Name]
	case *ast.SelectorExpr:
		switch {
		case n.fields[e.Sel.Name]:
			return pool
		case n.queriers[e.Sel.Name]:
			return querier
		}
	case *ast.CallExpr:
		sel, ok := e.Fun.(*ast.SelectorExpr)
		switch {
		case !ok:
		case n.getters[sel.Sel.Name] && len(e.Args) == 0:
			return pool
		case sel.Sel.Name == "New" && len(e.Args) == 1 && n.kind(e.Args[0], locals) == pool:
			return querier
		}
	}
	return other
}

// locals returns the variables in decl that hold the pool or a pool-bound
// querier on every assignment.
func (n names) locals(decl *ast.FuncDecl, f *file) map[string]kind {
	out := map[string]kind{}
	mixed := map[string]bool{}
	set := func(id ast.Expr, k kind) {
		name, ok := id.(*ast.Ident)
		if !ok {
			return
		}
		if prev, seen := out[name.Name]; k == other || (seen && prev != k) {
			mixed[name.Name] = true
		}
		out[name.Name] = k
	}
	params := func(ft *ast.FuncType) {
		for _, fld := range ft.Params.List {
			if f.isPool(fld.Type) {
				for _, name := range fld.Names {
					set(name, pool)
				}
			}
		}
	}
	params(decl.Type)
	ast.Inspect(decl.Body, func(node ast.Node) bool {
		switch x := node.(type) {
		case *ast.FuncLit:
			params(x.Type)
		case *ast.AssignStmt:
			for i, lhs := range x.Lhs {
				k := other
				if len(x.Lhs) == len(x.Rhs) {
					k = n.kind(x.Rhs[i], out)
				}
				set(lhs, k)
			}
		case *ast.ValueSpec:
			for i, name := range x.Names {
				k := other
				if len(x.Names) == len(x.Values) {
					k = n.kind(x.Values[i], out)
				}
				set(name, k)
			}
		}
		return true
	})
	for name := range mixed {
		delete(out, name)
	}
	return out
}

// isTx reports whether e is pgx.Tx.
func (f *file) isTx(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || f.pgx == "" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == f.pgx && sel.Sel.Name == "Tx"
}

// isPool reports whether e is *pgxpool.Pool.
func (f *file) isPool(e ast.Expr) bool {
	star, ok := e.(*ast.StarExpr)
	if !ok || f.pgxpool == "" {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == f.pgxpool && sel.Sel.Name == "Pool"
}

func (f *file) returnsPool(ft *ast.FuncType) bool {
	return ft.Results != nil && len(ft.Results.List) == 1 && f.isPool(ft.Results.List[0].Type)
}

// isQuerier reports whether e is *<pkg>.Queries, the type sqlc generates.
func isQuerier(e ast.Expr) bool {
	star, ok := e.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Queries"
}

// beginsTx returns the variable that "tx, err := x.Begin(ctx)" assigns, or "".
func beginsTx(as *ast.AssignStmt) string {
	if len(as.Rhs) != 1 || len(as.Lhs) == 0 {
		return ""
	}
	call, ok := as.Rhs[0].(*ast.CallExpr)
	if !ok {
		return ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || (sel.Sel.Name != "Begin" && sel.Sel.Name != "BeginTx") {
		return ""
	}
	if id, ok := as.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
		return id.Name
	}
	return ""
}

// blockEnd returns the end of the innermost block in stack.
func blockEnd(stack []ast.Node) token.Pos {
	for i := len(stack) - 1; i >= 0; i-- {
		switch stack[i].(type) {
		case *ast.BlockStmt, *ast.CaseClause, *ast.CommClause:
			return stack[i].End()
		}
	}
	return token.NoPos
}

// deferred reports whether stack is inside a defer statement.
func deferred(stack []ast.Node) bool {
	for _, n := range stack {
		if _, ok := n.(*ast.DeferStmt); ok {
			return true
		}
	}
	return false
}

func paramNames(fld *ast.Field) []string {
	if len(fld.Names) == 0 {
		return []string{"_"}
	}
	out := make([]string, len(fld.Names))
	for i, name := range fld.Names {
		out[i] = name.Name
	}
	return out
}

// localType returns the name of a same-package type T, *T or T[...], or "".
func localType(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.StarExpr:
		return localType(e.X)
	case *ast.IndexExpr:
		return localType(e.X)
	case *ast.IndexListExpr:
		return localType(e.X)
	case *ast.Ident:
		return e.Name
	}
	return ""
}

// receiver returns the receiver variable and type of a method, or "", "".
func receiver(fn *ast.FuncDecl) (string, string) {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return "", ""
	}
	r := fn.Recv.List[0]
	name := ""
	if len(r.Names) > 0 {
		name = r.Names[0].Name
	}
	return name, localType(r.Type)
}

// funcName returns Name, or Recv.Name for a method.
func funcName(fn *ast.FuncDecl) string {
	if _, typ := receiver(fn); typ != "" {
		return typ + "." + fn.Name.Name
	}
	return fn.Name.Name
}

// at renders pos as path:line.
func at(fset *token.FileSet, pos token.Pos) string {
	p := fset.Position(pos)
	return p.Filename + ":" + strconv.Itoa(p.Line)
}

// readAllowlist parses "path#Name  category: reason" lines into a map from
// key to line number.
func readAllowlist(t *testing.T, root string) map[string]int {
	t.Helper()
	allow := map[string]int{}
	sc := bufio.NewScanner(strings.NewReader(allowlist))
	for n := allowlistLine(t, root); sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, rest, _ := strings.Cut(line, " ")
		category, reason, _ := strings.Cut(strings.TrimSpace(rest), ":")
		switch {
		case !strings.Contains(key, "#"):
			t.Errorf("%s:%d: want path#Name, got %q", allowlistPath, n, key)
		case !categories[category]:
			t.Errorf("%s:%d: unknown category %q", allowlistPath, n, category)
		case strings.TrimSpace(reason) == "":
			t.Errorf("%s:%d: %s needs a reason after %q", allowlistPath, n, key, category+":")
		}
		if prev, ok := allow[key]; ok {
			t.Errorf("%s:%d: %s is already listed on line %d", allowlistPath, n, key, prev)
		}
		allow[key] = n
	}
	return allow
}

// walk calls fn for each file under dir, skipping generated, vendored and
// hidden directories. rel is slash-separated and relative to root.
func walk(t *testing.T, root, dir string, fn func(path, rel string)) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != dir && (strings.HasPrefix(name, ".") || name == "dbgen" || name == "vendor" || name == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		fn(path, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// repoRoot walks up from the working directory to the directory with go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// allowlistLine returns the line of allowlistPath where the allowlist constant
// starts, so entries are reported by their line in that file.
func allowlistLine(t *testing.T, root string) int {
	t.Helper()
	src := string(readFile(t, filepath.Join(root, allowlistPath)))
	for i, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(line, "const allowlist = `") {
			return i + 1
		}
	}
	t.Fatalf("%s: const allowlist not found", allowlistPath)
	return 0
}
