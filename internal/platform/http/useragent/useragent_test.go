package useragent

import "testing"

func TestParse(t *testing.T) {
	for ua, want := range map[string]struct{ label, kind string }{
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0 Safari/537.36":                       {"Chrome on macOS", "desktop"},
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0 Safari/537.36 Edg/154.0":                   {"Edge on Windows", "desktop"},
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1": {"Safari on iPhone", "mobile"},
		"Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/604.1":                        {"Safari on iPad", "tablet"},
		"Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0 Mobile Safari/537.36":                       {"Chrome on Android", "mobile"},
		"Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0":                                                                  {"Firefox on Linux", "desktop"},
		"curl/8.7.1": {"Unknown device", "unknown"},
		"":           {"Unknown device", "unknown"},
	} {
		d := Parse(ua)
		if d.Label() != want.label || d.Kind != want.kind {
			t.Errorf("Parse(%q) = %q %q, want %q %q", ua, d.Label(), d.Kind, want.label, want.kind)
		}
	}
}
