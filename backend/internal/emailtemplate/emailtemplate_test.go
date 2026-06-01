package emailtemplate

import "testing"

func TestRender(t *testing.T) {
	vars := map[string]string{"code": "123456", "ttl": "10m"}
	if got := Render("Your code is {{code}}, valid {{ttl}}.", vars); got != "Your code is 123456, valid 10m." {
		t.Errorf("substitution failed: %q", got)
	}
	// Spaces inside braces are tolerated.
	if got := Render("{{ code }}", vars); got != "123456" {
		t.Errorf("whitespace handling failed: %q", got)
	}
	// Unknown placeholders are left intact (visible, not blanked).
	if got := Render("Hi {{name}}", vars); got != "Hi {{name}}" {
		t.Errorf("unknown placeholder should be preserved: %q", got)
	}
	// No placeholders → unchanged.
	if got := Render("plain text", vars); got != "plain text" {
		t.Errorf("plain text changed: %q", got)
	}
}

func TestCatalogResolve(t *testing.T) {
	d, ok := defByKey("verify_email")
	if !ok {
		t.Fatal("verify_email must be in the catalog")
	}
	// No override → default, not custom.
	def := resolve(d, nil, nil)
	if def.Custom || def.Subject != d.DefaultSubject {
		t.Errorf("default resolve wrong: %+v", def)
	}
	// Override → custom content.
	subj, body := "Custom subject", "Custom body {{code}}"
	ov := resolve(d, &subj, &body)
	if !ov.Custom || ov.Subject != subj || ov.Body != body {
		t.Errorf("override resolve wrong: %+v", ov)
	}
	if _, ok := defByKey("nope"); ok {
		t.Error("unknown key should not resolve")
	}
}
