package httpx

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/qeetgroup/qeet-id/internal/platform/errs"
)

type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Detail  string `json:"detail,omitempty"`
		ReqID   string `json:"request_id,omitempty"`
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
	body.Error.ReqID = RequestID(r)
	WriteJSON(w, e.Status, body)
}

func DecodeJSON(r *http.Request, out any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return errs.ErrBadRequest.WithDetail(err.Error())
	}
	return nil
}
