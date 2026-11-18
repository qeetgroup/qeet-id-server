package email

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/delivery"
)

// listLimit is a list's page size: 50 unless the limit parameter asks for up
// to 100.
func listLimit(r *http.Request) int32 {
	return int32(paging.Limit(r.URL.Query(), 50, 100)) // #nosec G115 -- at most 100
}

// messagesPage is a page of messages to an address, with the address's
// suppression: null unless its mail is suppressed.
type messagesPage struct {
	paging.Result[delivery.MessageView]
	Suppression map[string]any `json:"suppression"`
}
