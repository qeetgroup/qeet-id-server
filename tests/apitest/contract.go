//go:build integration

package apitest

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/pb33f/libopenapi"
	validator "github.com/pb33f/libopenapi-validator"
	"github.com/pb33f/libopenapi-validator/paths"
	v3 "github.com/pb33f/libopenapi/datamodel/high/v3"
)

// Documents are the five API documents, in api/openapi.
var Documents = []string{"access", "identity", "federation", "developer", "operations"}

// contract is the API documents, each with its validator.
type contract struct {
	models     []*v3.Document
	validators []validator.Validator
}

var (
	loadOnce   sync.Once
	loaded     *contract
	loadFailed error
)

// loadContract parses the API documents once per test binary.
func loadContract(t testing.TB) *contract {
	t.Helper()
	loadOnce.Do(func() { loaded, loadFailed = parseDocuments() })
	if loadFailed != nil {
		t.Fatalf("apitest: read the API documents: %v", loadFailed)
	}
	return loaded
}

func parseDocuments() (*contract, error) {
	c := &contract{}
	for _, name := range Documents {
		raw, err := os.ReadFile(filepath.Join(RepoRoot(), "api", "openapi", name+".yaml")) // #nosec G304 -- the repository's own documents
		if err != nil {
			return nil, err
		}
		doc, err := libopenapi.NewDocument(raw)
		if err != nil {
			return nil, err
		}
		model, err := doc.BuildV3Model()
		if err != nil {
			return nil, err
		}
		c.models = append(c.models, &model.Model)
		c.validators = append(c.validators, validator.NewValidatorFromV3Model(&model.Model))
	}
	return c, nil
}

// Models are the parsed API documents, in the order of Documents.
func Models(t testing.TB) []*v3.Document {
	t.Helper()
	return loadContract(t).models
}

// check fails t unless one API document describes req and its answer res: the route, the status
// and the body.
func (c *contract) check(t testing.TB, req *http.Request, res *Response) {
	t.Helper()
	for i, model := range c.models {
		if item, _, _ := paths.FindPath(req, model, nil); item == nil {
			continue
		}
		resp := &http.Response{StatusCode: res.Status, Header: res.Header, Body: io.NopCloser(bytes.NewReader(res.Body)), Request: req}
		if ok, errs := c.validators[i].ValidateHttpResponse(req, resp); !ok {
			var lines []string
			for _, e := range errs {
				line := e.Message
				if e.Reason != "" && e.Reason != e.Message {
					line += ": " + e.Reason
				}
				for _, s := range e.SchemaValidationErrors {
					line += "\n      " + s.FieldPath + ": " + s.Reason
				}
				lines = append(lines, line)
			}
			t.Errorf("contract (%s.yaml): %s %s answered %d, which the document doesn't describe:\n    %s\n    body: %.300s",
				Documents[i], req.Method, req.URL.Path, res.Status, strings.Join(lines, "\n    "), res.Body)
		}
		return
	}
	t.Errorf("contract: %s %s is in no API document", req.Method, req.URL.Path)
}

// RepoRoot is the repository root, found from the working directory (a package under tests/).
func RepoRoot() string {
	dir, _ := os.Getwd()
	for d := dir; d != filepath.Dir(d); d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
	}
	return dir
}
