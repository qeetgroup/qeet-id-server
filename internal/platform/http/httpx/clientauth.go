package httpx

import (
	"net/http"
	"net/url"
)

// ClientBasicAuth is the client ID and secret an OAuth client sent with HTTP Basic. RFC 6749 §2.3.1
// form-encodes both before Basic-encoding, so they are decoded here (a value that isn't valid form
// encoding is taken as sent). ok is false without Basic credentials.
func ClientBasicAuth(r *http.Request) (clientID, clientSecret string, ok bool) {
	clientID, clientSecret, ok = r.BasicAuth()
	if !ok {
		return "", "", false
	}
	if decoded, err := url.QueryUnescape(clientID); err == nil {
		clientID = decoded
	}
	if decoded, err := url.QueryUnescape(clientSecret); err == nil {
		clientSecret = decoded
	}
	return clientID, clientSecret, true
}
