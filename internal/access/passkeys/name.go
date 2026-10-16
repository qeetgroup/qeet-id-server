package passkey

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// MaxNameLength is the longest passkey name accepted, in characters.
const MaxNameLength = 64

// fallbackName names a passkey enrolled from a browser that can't be told
// from its user agent.
const fallbackName = "Passkey"

// cleanName makes a user-supplied passkey name safe to store and to show as
// text. Control characters (NUL, line breaks, tabs, escapes) count as spaces;
// bidirectional controls are dropped, because they reorder the text shown
// around them; runs of spaces collapse into one, with none at either end.
// Markup is kept as typed: a name is text, and every UI shows it as text.
func cleanName(name string) string {
	var b strings.Builder
	space := false
	for _, r := range name {
		switch {
		case unicode.Is(unicode.Bidi_Control, r):
			continue
		case unicode.IsControl(r) || unicode.IsSpace(r):
			space = b.Len() > 0
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	return b.String()
}

// validName returns name cleaned, or a validation error when nothing is left
// of it or it is longer than MaxNameLength characters.
func validName(name string) (string, error) {
	name = cleanName(name)
	if name == "" {
		return "", nameError("required", "This field is required.")
	}
	if utf8.RuneCountInString(name) > MaxNameLength {
		return "", nameError("too_long", fmt.Sprintf("Must be at most %d characters.", MaxNameLength))
	}
	return name, nil
}

func nameError(code, message string) error {
	return errs.ErrValidationFailed.WithFields([]errs.FieldError{{Field: "name", Code: code, Message: message}})
}

// enrolmentName is the name a new passkey is stored with: the supplied name,
// checked like a rename, or DefaultName(userAgent) when none is supplied.
func enrolmentName(name, userAgent string) (string, error) {
	if cleanName(name) == "" {
		return DefaultName(userAgent), nil
	}
	return validName(name)
}

// Browser and platform tokens of a user agent, most specific first: a browser
// also names the ones it is built on (Edge and Opera say "Chrome", Chrome says
// "Safari"), and iOS says "Mac OS X" and Android "Linux".
var (
	uaBrowsers = []struct{ token, name string }{
		{"Edg/", "Edge"}, {"EdgA/", "Edge"}, {"EdgiOS/", "Edge"},
		{"OPR/", "Opera"}, {"OPiOS/", "Opera"},
		{"SamsungBrowser/", "Samsung Internet"},
		{"Firefox/", "Firefox"}, {"FxiOS/", "Firefox"},
		{"CriOS/", "Chrome"}, {"Chrome/", "Chrome"},
		{"Safari/", "Safari"},
	}
	uaPlatforms = []struct{ token, name string }{
		{"iPhone", "iPhone"}, {"iPad", "iPad"},
		{"Android", "Android"},
		{"CrOS", "ChromeOS"},
		{"Windows", "Windows"},
		{"Macintosh", "macOS"}, {"Mac OS X", "macOS"},
		{"Linux", "Linux"},
	}
)

// DefaultName names a passkey after the browser it was enrolled from, such as
// "Chrome on macOS", so that no passkey is listed without a name. It gives
// "Passkey on Android" when only the platform is known, and "Passkey" when
// neither is.
func DefaultName(userAgent string) string {
	browser, platform := uaToken(userAgent, uaBrowsers), uaToken(userAgent, uaPlatforms)
	switch {
	case platform == "":
		return fallbackName
	case browser == "":
		return fallbackName + " on " + platform
	default:
		return browser + " on " + platform
	}
}

func uaToken(userAgent string, tokens []struct{ token, name string }) string {
	for _, t := range tokens {
		if strings.Contains(userAgent, t.token) {
			return t.name
		}
	}
	return ""
}
