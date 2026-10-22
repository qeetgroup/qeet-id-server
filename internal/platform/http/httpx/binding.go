package httpx

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"time"
)

// BindingCookie ties a sign-in ceremony to the browser that began it, so a link
// or form post carrying another browser's ceremony fails Holds. The cookie is
// HttpOnly and, when Secure, __Host- prefixed, so scripts and sibling subdomains
// can't plant ids; it keeps the last few, so parallel ceremonies all finish.
type BindingCookie struct {
	Name     string        // without the __Host- prefix
	Secure   bool          // the cookie's Secure attribute
	SameSite http.SameSite // the cookie's SameSite attribute
	MaxAge   time.Duration // the cookie's lifetime
}

// bindingCookieKeep is how many ceremonies a browser can have in flight.
const bindingCookieKeep = 4

func (b BindingCookie) cookieName() string {
	if b.Secure {
		return "__Host-" + b.Name
	}
	return b.Name
}

func (b BindingCookie) held(r *http.Request) []string {
	c, err := r.Cookie(b.cookieName())
	if err != nil || c.Value == "" {
		return nil
	}
	return strings.Split(c.Value, ".")
}

// Add records that this browser began the ceremony id.
func (b BindingCookie) Add(w http.ResponseWriter, r *http.Request, id string) {
	if id == "" || strings.Contains(id, ".") {
		return
	}
	ids := append(b.held(r), id)
	if len(ids) > bindingCookieKeep {
		ids = ids[len(ids)-bindingCookieKeep:]
	}
	b.write(w, ids)
}

// Holds reports whether this browser began the ceremony id.
func (b BindingCookie) Holds(r *http.Request, id string) bool {
	if id == "" {
		return false
	}
	for _, held := range b.held(r) {
		if subtle.ConstantTimeCompare([]byte(held), []byte(id)) == 1 {
			return true
		}
	}
	return false
}

// Remove forgets a finished ceremony.
func (b BindingCookie) Remove(w http.ResponseWriter, r *http.Request, id string) {
	var kept []string
	for _, held := range b.held(r) {
		if held != id {
			kept = append(kept, held)
		}
	}
	b.write(w, kept)
}

func (b BindingCookie) write(w http.ResponseWriter, ids []string) {
	c := &http.Cookie{
		Name:     b.cookieName(),
		Value:    strings.Join(ids, "."),
		Path:     "/",
		Secure:   b.Secure,
		HttpOnly: true,
		SameSite: b.SameSite,
		MaxAge:   int(b.MaxAge.Seconds()),
	}
	if len(ids) == 0 {
		c.MaxAge = -1
	}
	http.SetCookie(w, c)
}
