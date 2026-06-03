package qeetid

import "fmt"

// Error is returned by every failed API call. Inspect Status or use the Is*
// helpers (errors.As(err, &qeetid.Error{}) to unwrap).
type Error struct {
	Status            int
	Code              string
	Message           string
	RequestID         string
	RetryAfterSeconds int // set on 429 when the server provided Retry-After
}

func (e *Error) Error() string {
	if e.RequestID != "" {
		return fmt.Sprintf("qeetid: %s (status %d, code %q, request %s)", e.Message, e.Status, e.Code, e.RequestID)
	}
	return fmt.Sprintf("qeetid: %s (status %d, code %q)", e.Message, e.Status, e.Code)
}

func (e *Error) IsUnauthorized() bool { return e.Status == 401 }
func (e *Error) IsForbidden() bool    { return e.Status == 403 }
func (e *Error) IsNotFound() bool     { return e.Status == 404 }
func (e *Error) IsRateLimited() bool  { return e.Status == 429 }
