package authpolicy

import "testing"

func TestValidatePassword_MinLength(t *testing.T) {
	p := Policy{PasswordMinLength: 12}
	if err := ValidatePassword(p, "short"); err == nil {
		t.Error("expected min-length failure")
	}
	if err := ValidatePassword(p, "twelve-chars!"); err != nil {
		t.Errorf("12+ chars should pass: %v", err)
	}
}

func TestValidatePassword_Complexity(t *testing.T) {
	p := Policy{
		PasswordMinLength:        8,
		PasswordRequireUppercase: true,
		PasswordRequireNumber:    true,
		PasswordRequireSymbol:    true,
	}
	cases := []struct {
		name string
		pw   string
		ok   bool
	}{
		{"all classes", "Abcdef1!", true},
		{"no uppercase", "abcdef1!", false},
		{"no number", "Abcdefg!", false},
		{"no symbol", "Abcdefg1", false},
		{"too short but complex", "Ab1!", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidatePassword(p, c.pw)
			if c.ok && err != nil {
				t.Errorf("%q should pass, got %v", c.pw, err)
			}
			if !c.ok && err == nil {
				t.Errorf("%q should fail", c.pw)
			}
		})
	}
}

func TestValidatePassword_DefaultsAreLenient(t *testing.T) {
	// DefaultPolicy: min 8, no complexity required.
	if err := ValidatePassword(DefaultPolicy(), "password"); err != nil {
		t.Errorf("8-char password should pass default policy: %v", err)
	}
	if err := ValidatePassword(DefaultPolicy(), "short"); err == nil {
		t.Error("sub-8 should still fail under defaults")
	}
}

func TestIsSymbol(t *testing.T) {
	if isSymbol('a') || isSymbol('1') || isSymbol(' ') {
		t.Error("letters, digits, spaces are not symbols")
	}
	if !isSymbol('!') || !isSymbol('@') {
		t.Error("punctuation should be a symbol")
	}
}
