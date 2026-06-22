package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"

	"github.com/go-playground/validator/v10"

	"github.com/qeetgroup/qeet-id/platform/errs"
)

type errorBody struct {
	Error struct {
		Code    string            `json:"code"`
		Message string            `json:"message"`
		Detail  string            `json:"detail,omitempty"`
		Fields  map[string]string `json:"fields,omitempty"`
		ReqID   string            `json:"request_id,omitempty"`
	} `json:"error"`
}

func WriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Warn("write json", "err", err)
	}
}

func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	e := errs.As(err)
	if e == nil {
		var domain *errs.Error
		if errors.As(err, &domain) {
			e = domain
		} else {
			slog.Error("unhandled error", "err", err, "path", r.URL.Path)
			e = errs.ErrInternal
		}
	}
	body := errorBody{}
	body.Error.Code = e.Code
	body.Error.Message = e.Message
	body.Error.Detail = e.Detail
	body.Error.Fields = e.Fields
	body.Error.ReqID = RequestID(r)
	WriteJSON(w, e.Status, body)
}

// ValidationError converts a go-playground/validator error into a clean,
// client-friendly 422 with a per-field message map (keyed by the JSON field
// name when the validator is configured with RegisterTagNameFunc). Non-
// validation errors fall back to a generic unprocessable error so callers can
// use it unconditionally after Validate.Struct.
func ValidationError(err error) error {
	var ve validator.ValidationErrors
	if errors.As(err, &ve) && len(ve) > 0 {
		fields := make(map[string]string, len(ve))
		for _, fe := range ve {
			fields[fe.Field()] = validationMessage(fe)
		}
		return errs.ErrValidation.WithFields(fields)
	}
	return errs.ErrUnprocessable
}

// validationMessage renders a human-readable message for a single field error.
func validationMessage(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return "This field is required."
	case "email":
		return "Must be a valid email address."
	case "min":
		if fe.Kind() == reflect.String {
			return fmt.Sprintf("Must be at least %s characters.", fe.Param())
		}
		return fmt.Sprintf("Must be at least %s.", fe.Param())
	case "max":
		if fe.Kind() == reflect.String {
			return fmt.Sprintf("Must be at most %s characters.", fe.Param())
		}
		return fmt.Sprintf("Must be at most %s.", fe.Param())
	case "uuid", "uuid4":
		return "Must be a valid identifier."
	case "url", "uri":
		return "Must be a valid URL."
	case "oneof":
		return fmt.Sprintf("Must be one of: %s.", fe.Param())
	case "e164":
		return "Must be a valid phone number in E.164 format."
	default:
		return "This value is invalid."
	}
}

func DecodeJSON(r *http.Request, out any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return errs.ErrBadRequest.WithDetail(err.Error())
	}
	return nil
}
