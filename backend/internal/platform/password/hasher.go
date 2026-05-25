// Package password wraps bcrypt with a single configurable cost.
package password

import "golang.org/x/crypto/bcrypt"

const cost = 12

func Hash(plain string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(plain), cost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

func Verify(hash, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}
