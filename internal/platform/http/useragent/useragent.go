// Package useragent describes the device behind a User-Agent header in words a
// person recognises ("Chrome on macOS"), so every surface names sessions and
// passkeys alike. Unrecognised tokens are described neutrally, never as errors.
package useragent

import "strings"

// Device is what a user agent says about the device.
type Device struct {
	// Browser and Platform are "" when not recognised.
	Browser  string
	Platform string
	// Kind is "desktop", "mobile", "tablet" or "unknown".
	Kind string
}

// Browser and platform tokens, most specific first: a browser also names the
// ones it is built on (Edge and Opera say "Chrome", Chrome says "Safari"),
// and iOS says "Mac OS X" and Android "Linux".
var (
	browsers = []struct{ token, name string }{
		{"Edg/", "Edge"}, {"EdgA/", "Edge"}, {"EdgiOS/", "Edge"},
		{"OPR/", "Opera"}, {"OPiOS/", "Opera"},
		{"SamsungBrowser/", "Samsung Internet"},
		{"Firefox/", "Firefox"}, {"FxiOS/", "Firefox"},
		{"CriOS/", "Chrome"}, {"Chrome/", "Chrome"},
		{"Safari/", "Safari"},
	}
	platforms = []struct{ token, name string }{
		{"iPhone", "iPhone"}, {"iPad", "iPad"},
		{"Android", "Android"},
		{"CrOS", "ChromeOS"},
		{"Windows", "Windows"},
		{"Macintosh", "macOS"}, {"Mac OS X", "macOS"},
		{"Linux", "Linux"},
	}
)

// Parse describes userAgent.
func Parse(userAgent string) Device {
	d := Device{Browser: token(userAgent, browsers), Platform: token(userAgent, platforms), Kind: "unknown"}
	lower := strings.ToLower(userAgent)
	switch {
	case d.Platform == "iPad" || strings.Contains(lower, "tablet"):
		d.Kind = "tablet"
	case d.Platform == "iPhone" || strings.Contains(lower, "mobile"):
		d.Kind = "mobile"
	case d.Platform != "":
		d.Kind = "desktop"
	}
	return d
}

// Label returns a readable description: "Chrome on macOS", "Android device"
// when only the platform is known, "Firefox" when only the browser is, and
// "Unknown device" when neither is.
func (d Device) Label() string {
	switch {
	case d.Browser != "" && d.Platform != "":
		return d.Browser + " on " + d.Platform
	case d.Platform != "":
		return d.Platform + " device"
	case d.Browser != "":
		return d.Browser
	default:
		return "Unknown device"
	}
}

func token(userAgent string, tokens []struct{ token, name string }) string {
	for _, t := range tokens {
		if strings.Contains(userAgent, t.token) {
			return t.name
		}
	}
	return ""
}
