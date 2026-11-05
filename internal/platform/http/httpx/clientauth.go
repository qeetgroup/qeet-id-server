package httpx

import (
	"net/http"
	"net/url"
)

// ClientBasicAuth is the client ID and secret an OAuth client sent with HTTP
// Basic authentication. RFC 6749 §2.3.1 has the client form-encode both before
// Basic-encoding them, so they are decoded here: a compliant client whose
// secret holds a reserved character is still recognised. A value that isn't
// valid form encoding is taken as sent. ok is false without Basic credentials.
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
