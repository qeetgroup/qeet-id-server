package bootstrap

import (
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// openAPIFile is one API document, kept as YAML nodes for the order it is
// written in, which the API reference follows, and as plain values to compare.
type openAPIFile struct {
	name  string
	root  *yaml.Node
	value map[string]any
}

// documentOperation is one operation, keyed "METHOD /path".
type documentOperation struct {
	key  string
	node *yaml.Node
}

func parseOpenAPIFile(name string, raw []byte) (openAPIFile, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return openAPIFile{}, err
	}
	if len(doc.Content) == 0 {
		return openAPIFile{}, fmt.Errorf("empty document")
	}
	var value map[string]any
	if err := doc.Decode(&value); err != nil {
		return openAPIFile{}, err
	}
	return openAPIFile{name: name, root: doc.Content[0], value: value}, nil
}

func loadOpenAPIFiles(t *testing.T) []openAPIFile {
	t.Helper()
	files := make([]openAPIFile, 0, len(openAPIDocuments))
	for _, name := range openAPIDocuments {
		raw, err := os.ReadFile(filepath.Join(openAPIDir(t), name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		file, err := parseOpenAPIFile(name, raw)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, file)
	}
	return files
}

// mappingValue returns the value under key in a YAML mapping, or nil.
func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

// operations lists the document's operations in the order they are written.
func (f openAPIFile) operations() []documentOperation {
	var ops []documentOperation
	paths := mappingValue(f.root, "paths")
	if paths == nil {
		return nil
	}
	for i := 0; i+1 < len(paths.Content); i += 2 {
		path, item := paths.Content[i].Value, paths.Content[i+1]
		for j := 0; j+1 < len(item.Content); j += 2 {
			method := strings.ToUpper(item.Content[j].Value)
			if slices.Contains(openAPIMethods, method) {
				ops = append(ops, documentOperation{key: method + " " + path, node: item.Content[j+1]})
			}
		}
	}
	return ops
}

// openAPIComponentConflicts reports components defined under the same name
// but differently in two documents. The API reference merges the documents and
// keeps the first definition, so a drifted copy misdescribes the other's operations.
func openAPIComponentConflicts(files []openAPIFile) []string {
	type definition struct {
		file  string
		value any
	}
	seen := map[string]definition{}
	var problems []string
	for _, f := range files {
		components, _ := f.value["components"].(map[string]any)
		for _, section := range slices.Sorted(maps.Keys(components)) {
			named, _ := components[section].(map[string]any)
			for _, name := range slices.Sorted(maps.Keys(named)) {
				key := section + "." + name
				first, ok := seen[key]
				if !ok {
					seen[key] = definition{file: f.name, value: named[name]}
					continue
				}
				if !reflect.DeepEqual(first.value, named[name]) {
					problems = append(problems, fmt.Sprintf("components.%s differs between %s and %s", key, first.file, f.name))
				}
			}
		}
	}
	return problems
}

// openAPIOperationIDProblems reports operations without an operationId, and
// operationIds used more than once across the documents.
func openAPIOperationIDProblems(files []openAPIFile) []string {
	owner := map[string]string{}
	var problems []string
	for _, f := range files {
		for _, op := range f.operations() {
			where := f.name + " " + op.key
			id := mappingValue(op.node, "operationId")
			if id == nil || id.Value == "" {
				problems = append(problems, where+" has no operationId")
				continue
			}
			if other, ok := owner[id.Value]; ok {
				problems = append(problems, fmt.Sprintf("operationId %s is used by %s and %s", id.Value, other, where))
				continue
			}
			owner[id.Value] = where
		}
	}
	return problems
}

// openAPITagProblems reports untagged operations, undeclared tags, and tags
// that first appear in a different order from the document's tags list. The
// API reference orders its sections by first appearance, so that list is the
// reading order.
func openAPITagProblems(f openAPIFile) []string {
	var declared []string
	if tags := mappingValue(f.root, "tags"); tags != nil {
		for _, tag := range tags.Content {
			if name := mappingValue(tag, "name"); name != nil {
				declared = append(declared, name.Value)
			}
		}
	}
	var problems, firstSeen []string
	for _, op := range f.operations() {
		tags := mappingValue(op.node, "tags")
		if tags == nil || len(tags.Content) == 0 {
			problems = append(problems, fmt.Sprintf("%s %s has no tag", f.name, op.key))
			continue
		}
		for _, tag := range tags.Content {
			if !slices.Contains(declared, tag.Value) {
				problems = append(problems, fmt.Sprintf("%s %s uses undeclared tag %q", f.name, op.key, tag.Value))
			}
			if !slices.Contains(firstSeen, tag.Value) {
				firstSeen = append(firstSeen, tag.Value)
			}
		}
	}
	if !slices.Equal(firstSeen, declared) {
		problems = append(problems, fmt.Sprintf("%s: tags first appear as %v but are declared as %v", f.name, firstSeen, declared))
	}
	return problems
}

// openAPIHeaderProblems reports where the documented headers disagree with
// the routes that send them: Cache-Control and Pragma on the success answers
// of exactly the noStore routes, and Idempotency-Key with Idempotent-Replayed
// on exactly the idempotent ones.
func openAPIHeaderProblems(files []openAPIFile, noStore, idempotent []string) []string {
	var problems []string
	for _, f := range files {
		paths, _ := f.value["paths"].(map[string]any)
		for _, op := range f.operations() {
			method, path, _ := strings.Cut(op.key, " ")
			item, _ := paths[path].(map[string]any)
			operation, _ := item[strings.ToLower(method)].(map[string]any)
			responses, _ := operation["responses"].(map[string]any)
			declares := func(header string) (every, some bool) {
				every = true
				for _, code := range slices.Sorted(maps.Keys(responses)) {
					if code[0] != '2' && code[0] != '3' {
						continue
					}
					response, _ := responses[code].(map[string]any)
					headers, _ := response["headers"].(map[string]any)
					_, has := headers[header]
					every, some = every && has, some || has
				}
				return every, some
			}
			hasKey := false
			parameters, _ := operation["parameters"].([]any)
			for _, p := range parameters {
				param, _ := p.(map[string]any)
				ref, _ := param["$ref"].(string)
				hasKey = hasKey || ref == "#/components/parameters/IdempotencyKey"
			}
			for _, check := range []struct {
				listed bool
				header string
			}{
				{slices.Contains(noStore, op.key), "Cache-Control"},
				{slices.Contains(noStore, op.key), "Pragma"},
				{slices.Contains(idempotent, op.key), "Idempotent-Replayed"},
			} {
				every, some := declares(check.header)
				if check.listed && !every {
					problems = append(problems, fmt.Sprintf("%s %s sends %s but a success answer doesn't declare it", f.name, op.key, check.header))
				}
				if !check.listed && some {
					problems = append(problems, fmt.Sprintf("%s %s declares %s but the route doesn't send it", f.name, op.key, check.header))
				}
			}
			if listed := slices.Contains(idempotent, op.key); listed != hasKey {
				problems = append(problems, fmt.Sprintf("%s %s: honours Idempotency-Key %v, documents it %v", f.name, op.key, listed, hasKey))
			}
		}
	}
	return problems
}

// unpagedLists are the lists answered whole, by design.
var unpagedLists = []string{
	"GET /v1/permissions",                                        // the platform's permission catalogue
	"GET /v1/tenants/{tenantID}/webhooks/events",                 // the webhook event catalogue
	"GET /v1/billing/plans",                                      // the plan catalogue
	"GET /v1/tenants/{tenantID}/email-templates",                 // one item per template key
	"GET /v1/tenants/{tenantID}/oidc/clients/{id}/auth-failures", // the last 20, as documented
}

// resolveRef follows node's local $ref within the document, if it has one.
func resolveRef(doc map[string]any, node any) map[string]any {
	for range 8 {
		m, _ := node.(map[string]any)
		ref, ok := m["$ref"].(string)
		if !ok {
			return m
		}
		node = doc
		for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			node = node.(map[string]any)[part]
		}
	}
	return nil
}

// openAPIListProblems reports lists, operations answering an items array,
// that neither page by cursor nor say when they were cut ("truncated"), and
// unpaged entries that no longer name such a list.
func openAPIListProblems(files []openAPIFile, unpaged []string) []string {
	var problems []string
	seen := map[string]bool{}
	for _, f := range files {
		paths, _ := f.value["paths"].(map[string]any)
		for _, op := range f.operations() {
			method, path, _ := strings.Cut(op.key, " ")
			if method != http.MethodGet {
				continue
			}
			item, _ := paths[path].(map[string]any)
			operation, _ := item["get"].(map[string]any)
			responses, _ := operation["responses"].(map[string]any)
			content, _ := resolveRef(f.value, responses["200"])["content"].(map[string]any)
			media, _ := content["application/json"].(map[string]any)
			properties, _ := resolveRef(f.value, media["schema"])["properties"].(map[string]any)
			if resolveRef(f.value, properties["items"])["type"] != "array" {
				continue
			}
			paged := properties["truncated"] != nil
			parameters, _ := operation["parameters"].([]any)
			for _, p := range parameters {
				paged = paged || resolveRef(f.value, p)["name"] == "cursor"
			}
			switch {
			case slices.Contains(unpaged, op.key) && paged:
				problems = append(problems, op.key+" pages now: take it off unpagedLists")
			case !slices.Contains(unpaged, op.key) && !paged:
				problems = append(problems, fmt.Sprintf("%s %s lists items with neither a cursor parameter nor truncated", f.name, op.key))
			}
			seen[op.key] = true
		}
	}
	for _, key := range unpaged {
		if !seen[key] {
			problems = append(problems, key+" is on unpagedLists but answers no items list")
		}
	}
	return problems
}

func TestOpenAPIDocumentsAreConsistent(t *testing.T) {
	files := loadOpenAPIFiles(t)
	problems := openAPIComponentConflicts(files)
	problems = append(problems, openAPIOperationIDProblems(files)...)
	for _, f := range files {
		problems = append(problems, openAPITagProblems(f)...)
	}
	problems = append(problems, openAPIHeaderProblems(files, NoStoreRoutes(), IdempotentRoutes())...)
	problems = append(problems, openAPIListProblems(files, unpagedLists)...)
	for _, p := range problems {
		t.Error(p)
	}
}

func TestOpenAPIConsistencyChecksDetectDrift(t *testing.T) {
	parse := func(name, raw string) openAPIFile {
		t.Helper()
		f, err := parseOpenAPIFile(name, []byte(raw))
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		return f
	}
	a := parse("a.yaml", `
tags: [{name: Users}, {name: Groups}]
paths:
  /groups:
    get: {operationId: listGroups, tags: [Groups]}
  /users:
    get: {operationId: listUsers, tags: [Users]}
    post: {operationId: createUser}
components:
  schemas:
    User: {type: object}
`)
	b := parse("b.yaml", `
tags: [{name: Users}]
paths:
  /me:
    get: {operationId: listUsers, tags: [Profile]}
components:
  schemas:
    User: {type: string}
`)

	want := []string{
		"components.schemas.User differs between a.yaml and b.yaml",
		"operationId listUsers is used by a.yaml GET /users and b.yaml GET /me",
		"a.yaml POST /users has no tag",
		"a.yaml: tags first appear as [Groups Users] but are declared as [Users Groups]",
		`b.yaml GET /me uses undeclared tag "Profile"`,
		"b.yaml: tags first appear as [Profile] but are declared as [Users]",
	}
	got := openAPIComponentConflicts([]openAPIFile{a, b})
	got = append(got, openAPIOperationIDProblems([]openAPIFile{a, b})...)
	got = append(got, openAPITagProblems(a)...)
	got = append(got, openAPITagProblems(b)...)
	if !slices.Equal(got, want) {
		t.Fatalf("problems =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestOpenAPIHeaderCheckDetectsDrift(t *testing.T) {
	f, err := parseOpenAPIFile("a.yaml", []byte(`
paths:
  /token:
    post:
      responses:
        '200': {description: OK}
  /list:
    get:
      responses:
        '200': {description: OK, headers: {Cache-Control: {}, Pragma: {}}}
  /keys:
    post:
      parameters: [{$ref: '#/components/parameters/IdempotencyKey'}]
      responses:
        '201': {description: Created}
`))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"a.yaml POST /token sends Cache-Control but a success answer doesn't declare it",
		"a.yaml POST /token sends Pragma but a success answer doesn't declare it",
		"a.yaml GET /list declares Cache-Control but the route doesn't send it",
		"a.yaml GET /list declares Pragma but the route doesn't send it",
		"a.yaml POST /keys sends Idempotent-Replayed but a success answer doesn't declare it",
		"a.yaml POST /token sends Idempotent-Replayed but a success answer doesn't declare it",
		"a.yaml POST /token: honours Idempotency-Key true, documents it false",
	}
	got := openAPIHeaderProblems([]openAPIFile{f}, []string{"POST /token"}, []string{"POST /keys", "POST /token"})
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("problems =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestOpenAPIListCheckDetectsDrift(t *testing.T) {
	f, err := parseOpenAPIFile("a.yaml", []byte(`
paths:
  /paged:
    get:
      parameters: [{$ref: '#/components/parameters/Cursor'}]
      responses: {'200': {content: {application/json: {schema: {properties: {items: {type: array}}}}}}}
  /capped:
    get:
      responses: {'200': {content: {application/json: {schema: {properties: {items: {type: array}, truncated: {type: boolean}}}}}}}
  /whole:
    get:
      responses: {'200': {content: {application/json: {schema: {properties: {items: {type: array}}}}}}}
  /catalogue:
    get:
      responses: {'200': {content: {application/json: {schema: {properties: {items: {type: array}}}}}}}
components:
  parameters:
    Cursor: {name: cursor, in: query}
`))
	if err != nil {
		t.Fatal(err)
	}
	got := openAPIListProblems([]openAPIFile{f}, []string{"GET /catalogue", "GET /paged", "GET /gone"})
	want := []string{
		"GET /paged pages now: take it off unpagedLists",
		"a.yaml GET /whole lists items with neither a cursor parameter nor truncated",
		"GET /gone is on unpagedLists but answers no items list",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("problems =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
