package emailtmpl

import (
	"strings"
	"testing"
)

func TestCode(t *testing.T) {
	out := Code("Verify your email", "Use the code below.", "123456", "10 minutes")
	for _, want := range []string{
		"123456", "10 minutes", "Verify your email",
		"class=\"q-otp\"",    // responsive code class
		"max-width:480px",    // fluid container
		"@media only screen", // mobile enhancement
		"width=device-width", // viewport
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Code() missing %q", want)
		}
	}
}

func TestActionEscapesURL(t *testing.T) {
	out := Action("Reset", "click below", "Reset password", "https://x.test/r?t=a&b=<c>", "ignore if not you")
	if !strings.Contains(out, "https://x.test/r?t=a&amp;b=&lt;c&gt;") {
		t.Error("url must be HTML-escaped in href + link text")
	}
	if !strings.Contains(out, "Reset password") {
		t.Error("button label missing")
	}
}

func TestInlineSVGLogo(t *testing.T) {
	SetLogoPNGURL("")
	out := Code("h", "i", "1", "1m")
	for _, want := range []string{"<svg", `viewBox="0 0 1254 1254"`, "#F26D0E" /* brand orange */, brandName} {
		if !strings.Contains(out, want) {
			t.Errorf("header missing %q (inline SVG mark + wordmark)", want)
		}
	}
	if strings.Contains(out, "background-image") {
		t.Error("no PNG background expected when logo PNG URL is unset")
	}
}

func TestPNGFallbackLayer(t *testing.T) {
	SetLogoPNGURL("https://app.test/logo192.png")
	defer SetLogoPNGURL("")
	out := Action("h", "i", "Go", "https://x.test/a", "note")
	// SVG on top, PNG background underneath (fallback for SVG-stripping clients).
	if !strings.Contains(out, `background-image:url('https://app.test/logo192.png')`) {
		t.Error("PNG fallback background missing when logo PNG URL is set")
	}
	if !strings.Contains(out, "<svg") {
		t.Error("inline SVG must still be layered on top")
	}
}
