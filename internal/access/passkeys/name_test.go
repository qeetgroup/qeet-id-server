package passkey

import (
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestDefaultName(t *testing.T) {
	for _, tc := range []struct{ ua, want string }{
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36", "Chrome on macOS"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15", "Safari on macOS"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1", "Safari on iPhone"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.6478.54 Mobile/15E148 Safari/604.1", "Chrome on iPhone"},
		{"Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1", "Safari on iPad"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.2592.68", "Edge on Windows"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0", "Firefox on Windows"},
		{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 OPR/111.0.0.0", "Opera on Linux"},
		{"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.71 Mobile Safari/537.36", "Chrome on Android"},
		{"Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36", "Samsung Internet on Android"},
		{"Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36", "Chrome on ChromeOS"},
		{"Mozilla/5.0 (Linux; Android 14)", "Passkey on Android"},
		{"curl/8.7.1", "Passkey"},
		{"", "Passkey"},
	} {
		if got := DefaultName(tc.ua); got != tc.want {
			t.Errorf("DefaultName(%q) = %q, want %q", tc.ua, got, tc.want)
		}
	}
}

func TestValidName(t *testing.T) {
	for _, tc := range []struct {
		in, want, code string // code: the field error code when refused
	}{
		{in: "Work laptop", want: "Work laptop"},
		{in: "  Desk key \t", want: "Desk key"},
		{in: "Work   laptop", want: "Work laptop"},
		{in: "Work\x00\nlaptop\t\u202e  evil\x7f", want: "Work laptop evil"},
		{in: "\u2066Phone\u2069", want: "Phone"},
		{in: `<img src=x onerror="alert(1)"> & <b>Key</b>`, want: `<img src=x onerror="alert(1)"> & <b>Key</b>`},
		{in: "👩\u200d💻 Studio", want: "👩\u200d💻 Studio"}, // a joiner inside an emoji is kept
		{in: strings.Repeat("é", MaxNameLength), want: strings.Repeat("é", MaxNameLength)},
		{in: " " + strings.Repeat("a", MaxNameLength) + " ", want: strings.Repeat("a", MaxNameLength)},
		{in: "", code: "required"},
		{in: " \t\r\n", code: "required"},
		{in: "\x00\u202e\x1b", code: "required"},
		{in: strings.Repeat("a", MaxNameLength+1), code: "too_long"},
	} {
		got, err := validName(tc.in)
		if tc.code == "" {
			if err != nil || got != tc.want {
				t.Errorf("validName(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
			}
			continue
		}
		e := errs.As(err)
		if e == nil || e.Code != errs.CodeValidation || len(e.Fields) != 1 || e.Fields[0].Field != "name" || e.Fields[0].Code != tc.code {
			t.Errorf("validName(%q) error = %v; want validation_failed on name (%s)", tc.in, err, tc.code)
		}
	}
}

func TestEnrolmentName(t *testing.T) {
	const ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	if got, err := enrolmentName("", ua); err != nil || got != "Chrome on macOS" {
		t.Errorf("no name: got %q, %v; want the browser default", got, err)
	}
	if got, err := enrolmentName(" \n ", ua); err != nil || got != "Chrome on macOS" {
		t.Errorf("blank name: got %q, %v; want the browser default", got, err)
	}
	if got, err := enrolmentName(" YubiKey 5 ", ua); err != nil || got != "YubiKey 5" {
		t.Errorf("supplied name: got %q, %v; want it cleaned", got, err)
	}
	if _, err := enrolmentName(strings.Repeat("a", MaxNameLength+1), ua); err == nil {
		t.Error("an over-long supplied name must be refused, not replaced")
	}
}
