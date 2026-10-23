package bootstrap

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/pb33f/libopenapi"
	validator "github.com/pb33f/libopenapi-validator"
)

// TestOpenAPIDocumentsAreValid checks every OpenAPI document against the
// OpenAPI 3.1 schema, and that every $ref in it resolves.
func TestOpenAPIDocumentsAreValid(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	files, err := filepath.Glob(filepath.Join(filepath.Dir(source), "..", "..", "api", "openapi", "*.yaml"))
	if err != nil || len(files) < 5 {
		t.Fatalf("found %d OpenAPI documents (%v)", len(files), err)
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			raw, err := os.ReadFile(file)
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
