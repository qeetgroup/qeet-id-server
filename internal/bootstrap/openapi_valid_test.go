package bootstrap

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/pb33f/libopenapi"
	validator "github.com/pb33f/libopenapi-validator"
)

// openAPIDocuments are the API documents in api/openapi, one per bounded context.
var openAPIDocuments = []string{"auth.yaml", "management.yaml", "federation.yaml", "developer.yaml", "operations.yaml"}

// openAPIDir is the api/openapi directory, found from this file so the tests
// run from any working directory.
func openAPIDir(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate the OpenAPI documents")
	}
	return filepath.Join(filepath.Dir(source), "..", "..", "api", "openapi")
}

// TestOpenAPIDocumentsAreValid checks every OpenAPI document against the
// OpenAPI 3.1 schema, and that every $ref in it resolves.
func TestOpenAPIDocumentsAreValid(t *testing.T) {
	for _, name := range openAPIDocuments {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(openAPIDir(t), name))
			if err != nil {
				t.Fatal(err)
			}
			doc, err := libopenapi.NewDocument(raw)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if _, err := doc.BuildV3Model(); err != nil {
				t.Errorf("model: %v", err)
			}
			v, errs := validator.NewValidator(doc)
			if len(errs) > 0 {
				t.Fatalf("validator: %v", errs)
			}
			if ok, problems := v.ValidateDocument(); !ok {
				for _, p := range problems {
					for _, f := range p.SchemaValidationErrors {
						t.Errorf("%s: %s", f.FieldPath, f.Reason)
					}
					if len(p.SchemaValidationErrors) == 0 {
						t.Errorf("%s: %s", p.Message, p.Reason)
					}
				}
			}
		})
	}
}
