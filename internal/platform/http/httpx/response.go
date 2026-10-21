package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/pgxerr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

type errorBody struct {
	Error struct {
		Code           string            `json:"code"`
		Message        string            `json:"message"`
		Detail         string            `json:"detail,omitempty"`
		TranslationKey string            `json:"translation_key,omitempty"`
		Retryable      bool              `json:"retryable,omitempty"`
		Fields         []errs.FieldError `json:"fields,omitempty"`
		Metadata       map[string]any    `json:"metadata,omitempty"`
		ReqID          string            `json:"request_id,omitempty"`
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
		switch {
		case errors.As(err, &domain):
			e = domain
		case pgxerr.IsLastOwner(err):
			// The database's own guard (migration 0151): whichever path tried to
			// take away the organisation's last active owner is told why.
			e = errs.ErrTenantLastOwner
		default:
			attrs := []any{
				"err", err,
				"route", safeRequestRoute(r),
				"req_id", RequestID(r),
				"client_ip", ClientIP(r),
			}
			if p := PrincipalFromCtx(r.Context()); p != nil {
				if p.TenantID != nil {
					attrs = append(attrs, "tenant_id", p.TenantID.String())
				}
				if p.UserID != nil {
					attrs = append(attrs, "user_id", p.UserID.String())
				}
			}
			slog.Error("unhandled error", attrs...)
			e = errs.ErrInternalServer
		}
	}
	// A domain error that carries a wrapped cause attached one deliberately for
	// diagnosis (errs.Wrap) — the cause is never serialized to the client, so log
	// it here or it's lost. This is how e.g. passkey.attestation_invalid surfaces
	// the underlying go-webauthn reason (origin/RPID/challenge mismatch) that the
	// generic client message hides.
	if cause := e.Unwrap(); cause != nil {
		slog.Warn("request error",
			// "error_code", not "code": the redacting log handler treats "code"
			// as a secret (OTPs, OAuth codes), which blanked this field and made
			// the line useless for the correlation it exists to provide.
			"error_code", e.Code,
			"cause", cause,
			"route", safeRequestRoute(r),
			"req_id", RequestID(r),
			"client_ip", ClientIP(r),
		)
	}
	body := errorBody{}
	body.Error.Code = e.Code
	body.Error.Message = e.Message
	body.Error.Detail = e.Detail
	body.Error.TranslationKey = e.TranslationKey
	body.Error.Retryable = e.Retryable
	body.Error.Fields = e.Fields
	body.Error.Metadata = e.Metadata
	body.Error.ReqID = RequestID(r)
	WriteJSON(w, statusForCode(e.Code), body)
}

// ValidationError converts a go-playground/validator error into a clean,
// client-friendly 422 with a per-field message map (keyed by the JSON field
// name when the validator is configured with RegisterTagNameFunc). Non-
// validation errors fall back to a generic unprocessable error so callers can
// use it unconditionally after Validate.Struct.
func ValidationError(err error) error {
	var ve validator.ValidationErrors
	if errors.As(err, &ve) && len(ve) > 0 {
		fields := make([]errs.FieldError, 0, len(ve))
		for _, fe := range ve {
			fields = append(fields, errs.FieldError{
				Field:   fe.Field(),
				Code:    validationCode(fe),
				Message: validationMessage(fe),
			})
		}
		return errs.ErrValidationFailed.WithFields(fields)
	}
	return errs.ErrUnprocessable
}

// validationCode returns a stable, machine-readable reason for a field error so
// clients can localize/react without parsing the human message.
func validationCode(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return "required"
	case "email":
		return "invalid_email"
	case "min":
		return "too_short"
	case "max":
		return "too_long"
	case "uuid", "uuid4":
		return "invalid_uuid"
	case "url", "uri":
		return "invalid_url"
	case "oneof":
		return "not_allowed"
	case "e164":
		return "invalid_phone"
	default:
		return "invalid"
	}
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

const (
	MaxJSONBodyBytes = int64(1 << 20)
	MaxFormBodyBytes = int64(64 << 10)
	MaxSAMLBodyBytes = int64(1 << 20)
)

func DecodeJSON(r *http.Request, out any) error {
	return DecodeJSONLimit(r, out, MaxJSONBodyBytes)
}

// DecodeStrictJSON is DecodeJSON for the routes that sign a browser in: a body
// not declared as JSON is refused as an unsupported media type. A page on
// another site can make a browser post a text/plain or form body without asking
// first, but not an application/json one, so those routes can't be reached by
// a cross-site form.
func DecodeStrictJSON(r *http.Request, out any) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/json" &&
		(!strings.HasPrefix(mediaType, "application/") || !strings.HasSuffix(mediaType, "+json"))) {
		return errs.ErrUnsupportedMediaType
	}
	return DecodeJSON(r, out)
}

func DecodeJSONLimit(r *http.Request, out any, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = MaxJSONBodyBytes
	}
	if r.ContentLength > maxBytes {
		return errs.ErrRequestBodyTooLarge
	}
	limited := &io.LimitedReader{R: r.Body, N: maxBytes + 1}
	dec := json.NewDecoder(limited)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		if limited.N == 0 {
			return errs.ErrRequestBodyTooLarge
		}
		return errs.ErrBadRequest.WithDetail(err.Error())
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if limited.N == 0 {
			return errs.ErrRequestBodyTooLarge
		}
		return errs.ErrBadRequest.WithDetail("request body must contain exactly one JSON value")
	}
	if limited.N == 0 {
		return errs.ErrRequestBodyTooLarge
	}
	return nil
}

func ParseForm(r *http.Request, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = MaxFormBodyBytes
	}
	if r.ContentLength > maxBytes {
		return errs.ErrRequestBodyTooLarge
	}
	r.Body = http.MaxBytesReader(nil, r.Body, maxBytes)
	if err := r.ParseForm(); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return errs.ErrRequestBodyTooLarge
		}
		return errs.ErrBadRequest.WithDetail("invalid form body")
	}
	return nil
}
