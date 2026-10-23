// Package tenantguard_test fails when SQL that touches a tenant-owned table
// does not filter on tenant_id. Qeet ID has no row-level security, so a missing
// tenant condition is a cross-tenant leak that the database will not catch.
package tenantguard_test

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const (
	allowlistPath  = "internal/platform/database/tenantguard/allowlist_test.go"
	migrationsGlob = "internal/platform/database/migrations/*.up.sql"
)

// categories are the accepted reasons for a query to skip tenant_id.
var categories = map[string]bool{
	"secret-lookup":     true,
	"session-scoped":    true,
	"background-sweep":  true,
	"parent-scoped":     true,
	"global-client":     true,
	"pre-tenant":        true,
	"global-table-join": true,
	"platform-wide":     true,
	"pending-review":    true,
}

// sqlCalls are the pgx methods whose SQL argument is checked.
var sqlCalls = map[string]bool{"Query": true, "QueryRow": true, "Exec": true}

var (
	createTableRe = regexp.MustCompile(`(?i)\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w."]+)\s*\(`)
	alterTableRe  = regexp.MustCompile(`(?i)\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?([\w."]+)([^;]*)`)
	addTenantRe   = regexp.MustCompile(`(?i)\bADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?"?tenant_id"?\s`)
	tableRefRe    = regexp.MustCompile(`"?(\w+)"?\."?(\w+)"?`)
	sqlTokenRe    = regexp.MustCompile(`"(\w+)"|\w+|[();]`)
	sqlVerbRe     = regexp.MustCompile(`(?i)\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b`)
	sqlTableRe    = regexp.MustCompile(`(?i)\b(FROM|INTO|UPDATE|JOIN)\s+"?\w+"?\.`)
	sqlcNameRe    = regexp.MustCompile(`^--\s*name:\s*(\w+)`)
	lineCommentRe = regexp.MustCompile(`--[^\n]*`)
	blockCommRe   = regexp.MustCompile(`(?s)/\*.*?\*/`)
	sqlStringRe   = regexp.MustCompile(`'(?:[^']|'')*'`)
)

// query is one SQL statement found in the repository.
type query struct {
	key  string // path#Name, the allowlist key
	pos  string // path:line, for messages
	text string // SQL without comments and string literals
}

// TestTenantFilter requires tenant_id in a WHERE, ON or USING clause at any depth
// (subqueries and CTEs count; the select list, SET and RETURNING do not). An INSERT
// names it in its column list instead, an INSERT … SELECT from a tenant-owned table
// also filters it, and ON CONFLICT … DO UPDATE names it in the target or WHERE.
func TestTenantFilter(t *testing.T) {
	root := repoRoot(t)
	tables := tenantTables(t, root)
	sqlc, inline := sqlcQueries(t, root), goQueries(t, root)
	if len(tables) == 0 || len(sqlc) == 0 || len(inline) == 0 {
		t.Fatalf("found %d tenant-owned tables, %d sqlc queries and %d Go queries; the scanner is broken",
			len(tables), len(sqlc), len(inline))
	}
	queries := append(sqlc, inline...)
	allow := readAllowlist(t, root)
	for _, problem := range check(tables, queries, allow) {
		t.Error(problem)
	}
	t.Logf("checked %d queries against %d tenant-owned tables; %d allowlisted", len(queries), len(tables), len(allow))
}

// TestTenantFilterRule runs check on fixed SQL: tenant_id that is only read back
// is flagged, and tenant_id in a WHERE, a join condition or an INSERT's columns
// is not.
func TestTenantFilterRule(t *testing.T) {
	tables := map[string]bool{"tenant.widgets": true, "tenant.parts": true}
	for _, c := range []struct {
		sql    string
		scoped bool
	}{
		{`SELECT id, tenant_id FROM tenant.widgets WHERE id = $1`, false},
		{`UPDATE tenant.widgets SET name = $2 WHERE id = $1 RETURNING tenant_id`, false},
		{`DELETE FROM tenant.widgets WHERE id = $1 RETURNING tenant_id`, false},
		{`SELECT DISTINCT ON (tenant_id) id FROM tenant.widgets WHERE id = $1`, false},
		{`SELECT id FROM tenant.widgets WHERE tenant_id = $1 AND id = $2`, true},
		{`SELECT p.id FROM tenant.parts p JOIN tenant.widgets t ON t.tenant_id = p.tenant_id AND t.id = p.widget_id WHERE p.id = $1`, true},
		{`SELECT id FROM tenant.widgets WHERE id IN (SELECT widget_id FROM tenant.parts WHERE tenant_id = $1)`, true},
		{`INSERT INTO tenant.widgets (tenant_id, name) VALUES ($1, $2) RETURNING id`, true},
		{`INSERT INTO tenant.widgets (tenant_id, name) SELECT tenant_id, name FROM tenant.parts WHERE id = $1`, false},
		{`INSERT INTO tenant.widgets (tenant_id, name) VALUES ($1, $2) ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name`, false},
		{`INSERT INTO tenant.widgets (tenant_id, name) VALUES ($1, $2) ON CONFLICT (tenant_id, name) DO UPDATE SET name = EXCLUDED.name`, true},
	} {
		q := query{key: "rule#Query", pos: "rule:1", text: cleanSQL(c.sql)}
		if scoped := len(check(tables, []query{q}, map[string]int{})) == 0; scoped != c.scoped {
			t.Errorf("scoped = %v, want %v: %s", scoped, c.scoped, c.sql)
		}
	}
}

// check returns one message per unscoped query that is not allowlisted and
// per stale allowlist entry. allow maps each key to its line number.
func check(tables map[string]bool, queries []query, allow map[string]int) []string {
	var problems []string
	found := map[string]bool{}
	unscoped := map[string]bool{}
	for _, q := range queries {
		found[q.key] = true
		table := unscopedTable(tables, q.text)
		if table == "" {
			continue
		}
		unscoped[q.key] = true
		if _, ok := allow[q.key]; !ok {
			problems = append(problems, fmt.Sprintf(
				"%s: query on tenant-owned table %s does not filter on tenant_id.\n"+
					"\tAdd a tenant_id condition, with the tenant from httpx.RequireTenant.\n"+
					"\tIf the query is safe without one, add this line to %s\n"+
					"\t(categories are listed at the top of the file):\n"+
					"\t%s  <category>: <why it is safe>",
				q.pos, table, allowlistPath, q.key))
		}
	}
	for key, line := range allow {
		switch {
		case !found[key]:
			problems = append(problems, fmt.Sprintf(
				"%s:%d: %s matches no query (renamed or removed?); delete the line.", allowlistPath, line, key))
		case !unscoped[key]:
			problems = append(problems, fmt.Sprintf(
				"%s:%d: %s now filters on tenant_id; delete the line.", allowlistPath, line, key))
		}
	}
	sort.Strings(problems)
	return problems
}

// unscopedTable returns a tenant-owned table read or written by a statement in
// sql that is not scoped to a tenant, or "" when every statement is.
func unscopedTable(tables map[string]bool, sql string) string {
	for _, stmt := range statements(sql) {
		if table := tenantTable(tables, stmt); table != "" && !scoped(tables, stmt) {
			return table
		}
	}
	return ""
}

// statements splits sql at each semicolon outside parentheses.
func statements(sql string) []string {
	var out []string
	depth, start := 0, 0
	for i, r := range sql {
		switch {
		case r == '(':
			depth++
		case r == ')' && depth > 0:
			depth--
		case r == ';' && depth == 0:
			out = append(out, sql[start:i])
			start = i + 1
		}
	}
	return append(out, sql[start:])
}

// sqlToken is a word, quoted identifier or parenthesis and its byte offset.
type sqlToken struct {
	word   string // upper-cased; a quoted identifier is never a keyword
	quoted bool
	at     int
}

func sqlTokens(sql string) []sqlToken {
	var out []sqlToken
	for _, m := range sqlTokenRe.FindAllStringSubmatchIndex(sql, -1) {
		tok := sqlToken{word: strings.ToUpper(sql[m[0]:m[1]]), at: m[0]}
		if m[2] >= 0 {
			tok.word, tok.quoted = strings.ToUpper(sql[m[2]:m[3]]), true
		}
		out = append(out, tok)
	}
	return out
}

// scoped applies the rule described on TestTenantFilter to one statement. It
// tracks the clause each parenthesis level is in, so tenant_id inside a WHERE
// or a subquery's WHERE is a filter and tenant_id in a select list is not.
func scoped(tables map[string]bool, sql string) bool {
	toks := sqlTokens(sql)
	word := func(i int) string {
		if i < 0 || i >= len(toks) || toks[i].quoted {
			return ""
		}
		return toks[i].word
	}
	clause := []string{""} // the clause at each parenthesis depth
	var (
		verb                         string // the depth-0 SELECT, INSERT, UPDATE or DELETE
		filters                      []int  // offsets of tenant_id used as a filter
		target                       string // INSERT: text naming the target table
		targetAt                     = -1
		inColumns                    bool // INSERT: tenant_id in the column list
		source, sourceEnd            = -1, len(sql)
		conflictUpdate, conflictUses bool
	)
	for i, tok := range toks {
		depth := len(clause) - 1
		top := &clause[depth]
		w := word(i)
		switch {
		case tok.word == "TENANT_ID":
			switch *top {
			case "WHERE", "ON", "USING":
				filters = append(filters, tok.at)
				conflictUses = conflictUses || (conflictUpdate && depth == 0)
			case "INTO":
				inColumns = inColumns || (verb == "INSERT" && depth == 1)
			case "CONFLICT":
				conflictUses = true
			}
		case w == "(":
			clause = append(clause, *top)
		case w == ")":
			if depth > 0 {
				clause = clause[:depth]
			}
		case w == "ON":
			switch {
			case word(i+1) == "CONFLICT":
				*top = "CONFLICT"
				if depth == 0 && source >= 0 && sourceEnd == len(sql) {
					sourceEnd = tok.at
				}
			case word(i-1) == "DISTINCT":
				*top = "DISTINCT"
			default:
				*top = "ON"
			}
		case w == "UPDATE" && word(i-1) == "DO":
			*top = "SET"
			conflictUpdate = conflictUpdate || depth == 0
		case w == "UPDATE" && (word(i-1) == "FOR" || word(i-1) == "KEY"):
			*top = "LOCK"
		case w == "RETURNING":
			*top = w
			if depth == 0 && source >= 0 && sourceEnd == len(sql) {
				sourceEnd = tok.at
			}
		case w == "SELECT", w == "INSERT", w == "UPDATE", w == "DELETE":
			*top = w
			if depth == 0 && verb == "" {
				verb = w
			} else if depth == 0 && verb == "INSERT" && w == "SELECT" && source < 0 {
				source = tok.at
			}
		case w == "INTO", w == "FROM", w == "WHERE", w == "USING", w == "JOIN", w == "SET",
			w == "VALUES", w == "GROUP", w == "ORDER", w == "HAVING", w == "LIMIT", w == "WINDOW":
			*top = w
			if w == "INTO" && depth == 0 && verb == "INSERT" && targetAt < 0 {
				targetAt = tok.at
			}
		}
		endsTarget := w == "(" || w == "SELECT" || w == "VALUES" || w == "DEFAULT"
		if targetAt >= 0 && target == "" && depth == 0 && endsTarget && tok.at > targetAt {
			target = sql[targetAt:tok.at]
		}
	}
	if verb != "INSERT" {
		return len(filters) > 0
	}
	if target == "" {
		target = sql // target not found: treat any tenant-owned table as the target
	}
	ok := inColumns || tenantTable(tables, target) == ""
	if source >= 0 && tenantTable(tables, sql[source:sourceEnd]) != "" {
		ok = ok && slices.ContainsFunc(filters, func(at int) bool { return at >= source && at < sourceEnd })
	}
	return ok && (!conflictUpdate || conflictUses)
}

// tenantTable returns the first tenant-owned table the SQL references, or "".
func tenantTable(tables map[string]bool, sql string) string {
	for _, m := range tableRefRe.FindAllStringSubmatch(sql, -1) {
		name := strings.ToLower(m[1] + "." + m[2])
		if tables[name] {
			return name
		}
	}
	return ""
}

// tenantTables returns the schema-qualified tables that have a tenant_id
// column, either at creation or through a later ALTER TABLE.
func tenantTables(t *testing.T, root string) map[string]bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(root, migrationsGlob))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	tables := map[string]bool{}
	for _, file := range files {
		sql := stripComments(readFile(t, file))
		for _, loc := range createTableRe.FindAllStringSubmatchIndex(sql, -1) {
			if hasTenantColumn(sql[loc[1]:]) {
				tables[tableName(sql[loc[2]:loc[3]])] = true
			}
		}
		for _, m := range alterTableRe.FindAllStringSubmatch(sql, -1) {
			if addTenantRe.MatchString(m[2]) {
				tables[tableName(m[1])] = true
			}
		}
	}
	return tables
}

// hasTenantColumn reports whether the column list that body starts with
// (just after the opening parenthesis) defines a tenant_id column.
func hasTenantColumn(body string) bool {
	depth, start := 0, 0
	for i, r := range body {
		switch {
		case r == '(':
			depth++
		case r == ')' && depth > 0:
			depth--
		case depth == 0 && (r == ',' || r == ')'):
			fields := strings.Fields(body[start:i])
			if len(fields) > 0 && strings.EqualFold(strings.Trim(fields[0], `"`), "tenant_id") {
				return true
			}
			if r == ')' {
				return false
			}
			start = i + 1
		}
	}
	return false
}

func tableName(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, `"`, ""))
}

// sqlcQueries returns every "-- name:" block in every queries.sql.
func sqlcQueries(t *testing.T, root string) []query {
	t.Helper()
	var out []query
	walk(t, root, func(path, rel string) {
		if filepath.Base(path) != "queries.sql" {
			return
		}
		var cur *query
		var body strings.Builder
		flush := func() {
			if cur != nil {
				cur.text = cleanSQL(body.String())
				out = append(out, *cur)
			}
			body.Reset()
		}
		sc := bufio.NewScanner(strings.NewReader(readFile(t, path)))
		for n := 1; sc.Scan(); n++ {
			if m := sqlcNameRe.FindStringSubmatch(sc.Text()); m != nil {
				flush()
				cur = &query{key: rel + "#" + m[1], pos: rel + ":" + strconv.Itoa(n)}
				continue
			}
			body.WriteString(sc.Text() + "\n")
		}
		flush()
	})
	return out
}

// goQueries returns the SQL in hand-written Go, keyed by the enclosing
// function (or by the name of a package-level const or var). It takes the SQL
// argument of each Query, QueryRow and Exec call, then any other SQL string
// that no call used, such as a statement in a slice that a loop executes.
func goQueries(t *testing.T, root string) []query {
	t.Helper()
	fset := token.NewFileSet()
	type file struct {
		rel string
		ast *ast.File
	}
	packages := map[string][]file{}
	walk(t, root, func(path, rel string) {
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		packages[filepath.Dir(path)] = append(packages[filepath.Dir(path)], file{rel, f})
	})
	var out []query
	for _, files := range packages {
		pkg := map[string][]ast.Expr{}
		for _, f := range files {
			for _, decl := range f.ast.Decls {
				if gen, ok := decl.(*ast.GenDecl); ok {
					collectSpecs(gen, pkg)
				}
			}
		}
		used := map[token.Pos]bool{}
		add := func(rel, name string, pos token.Pos, sql string) {
			out = append(out, query{
				key:  rel + "#" + name,
				pos:  rel + ":" + strconv.Itoa(fset.Position(pos).Line),
				text: cleanSQL(sql),
			})
		}
		for _, f := range files {
			for _, decl := range f.ast.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				r := &resolver{pkg: pkg, local: localStrings(fn.Body), active: map[string]bool{}, mark: used}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok || !sqlCalls[calleeName(call)] {
						return true
					}
					for _, arg := range call.Args {
						if sql := r.text(arg); sql != "" {
							add(f.rel, funcName(fn), call.Pos(), sql)
							break
						}
					}
					return true
				})
			}
		}
		for _, f := range files {
			for _, decl := range f.ast.Decls {
				r := &resolver{pkg: pkg, active: map[string]bool{}}
				switch decl := decl.(type) {
				case *ast.FuncDecl:
					if decl.Body != nil {
						r.local = localStrings(decl.Body)
						for _, e := range r.unusedSQL(decl.Body, used) {
							add(f.rel, funcName(decl), e.Pos(), r.text(e))
						}
					}
				case *ast.GenDecl:
					for _, spec := range decl.Specs {
						if vs, ok := spec.(*ast.ValueSpec); ok {
							for _, e := range r.unusedSQL(vs, used) {
								add(f.rel, vs.Names[0].Name, e.Pos(), r.text(e))
							}
						}
					}
				}
			}
		}
	}
	return out
}

// localStrings maps each variable in body to every expression assigned to it.
func localStrings(body *ast.BlockStmt) map[string][]ast.Expr {
	vars := map[string][]ast.Expr{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if len(n.Lhs) == len(n.Rhs) {
				for i, lhs := range n.Lhs {
					if id, ok := lhs.(*ast.Ident); ok {
						vars[id.Name] = append(vars[id.Name], n.Rhs[i])
					}
				}
			}
		case *ast.RangeStmt:
			if id, ok := n.Value.(*ast.Ident); ok {
				vars[id.Name] = append(vars[id.Name], n.X)
			}
		case *ast.GenDecl:
			collectSpecs(n, vars)
		}
		return true
	})
	return vars
}

func collectSpecs(gen *ast.GenDecl, vars map[string][]ast.Expr) {
	for _, spec := range gen.Specs {
		if vs, ok := spec.(*ast.ValueSpec); ok && len(vs.Names) == len(vs.Values) {
			for i, name := range vs.Names {
				vars[name.Name] = append(vars[name.Name], vs.Values[i])
			}
		}
	}
}

// resolver turns a Go expression into the SQL text it can build, following
// string concatenation, constants and local variables.
type resolver struct {
	pkg, local map[string][]ast.Expr
	active     map[string]bool    // identifiers being resolved, to stop cycles
	mark       map[token.Pos]bool // if set, records every string literal read
}

// unusedSQL returns each outermost string expression in node that looks like
// SQL and contains no literal in used.
func (r *resolver) unusedSQL(node ast.Node, used map[token.Pos]bool) []ast.Expr {
	var out []ast.Expr
	ast.Inspect(node, func(n ast.Node) bool {
		e, ok := n.(ast.Expr)
		if !ok || !isString(e) {
			return true
		}
		sql := r.text(e)
		if sql == "" {
			return true
		}
		if !usesAny(e, used) && sqlVerbRe.MatchString(sql) && sqlTableRe.MatchString(sql) {
			out = append(out, e)
		}
		return false
	})
	return out
}

// isString reports whether e is a string literal or a concatenation.
func isString(e ast.Expr) bool {
	switch e := e.(type) {
	case *ast.BasicLit:
		return e.Kind == token.STRING
	case *ast.BinaryExpr:
		return e.Op == token.ADD
	}
	return false
}

func usesAny(e ast.Expr, used map[token.Pos]bool) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && used[lit.Pos()] {
			found = true
		}
		return !found
	})
	return found
}

func (r *resolver) text(e ast.Expr) string {
	var b strings.Builder
	switch e := e.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			if r.mark != nil {
				r.mark[e.Pos()] = true
			}
			s, _ := strconv.Unquote(e.Value)
			return s
		}
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			return r.text(e.X) + r.text(e.Y)
		}
	case *ast.ParenExpr:
		return r.text(e.X)
	case *ast.KeyValueExpr:
		return r.text(e.Value)
	case *ast.CallExpr:
		for _, arg := range e.Args {
			b.WriteString(r.text(arg))
		}
	case *ast.CompositeLit:
		for _, elt := range e.Elts {
			b.WriteString(r.text(elt) + " ")
		}
	case *ast.Ident:
		if r.active[e.Name] {
			return ""
		}
		r.active[e.Name] = true
		defer delete(r.active, e.Name)
		exprs, ok := r.local[e.Name]
		if !ok {
			exprs = r.pkg[e.Name]
		}
		for _, x := range exprs {
			b.WriteString(r.text(x))
		}
	}
	return b.String()
}

func calleeName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		return fn.Sel.Name
	case *ast.Ident:
		return fn.Name
	}
	return ""
}

// funcName returns Name, or Recv.Name for a method.
func funcName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	recv := fn.Recv.List[0].Type
	if star, ok := recv.(*ast.StarExpr); ok {
		recv = star.X
	}
	if index, ok := recv.(*ast.IndexExpr); ok {
		recv = index.X
	}
	if id, ok := recv.(*ast.Ident); ok {
		return id.Name + "." + fn.Name.Name
	}
	return fn.Name.Name
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

// cleanSQL drops comments and string literals so neither can satisfy the check.
func cleanSQL(sql string) string {
	return sqlStringRe.ReplaceAllString(stripComments(sql), "''")
}

func stripComments(sql string) string {
	return blockCommRe.ReplaceAllString(lineCommentRe.ReplaceAllString(sql, ""), "")
}

// walk calls fn for each file under root, skipping generated, vendored and
// hidden directories. rel is slash-separated and relative to root.
func walk(t *testing.T, root string, fn func(path, rel string)) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "dbgen" || name == "vendor" || name == "node_modules" || name == "testdata") {
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

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// allowlistLine returns the line of allowlistPath where the allowlist constant
// starts, so entries are reported by their line in that file.
func allowlistLine(t *testing.T, root string) int {
	t.Helper()
	src := readFile(t, filepath.Join(root, allowlistPath))
	for i, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(line, "const allowlist = `") {
			return i + 1
		}
	}
	t.Fatalf("%s: const allowlist not found", allowlistPath)
	return 0
}
