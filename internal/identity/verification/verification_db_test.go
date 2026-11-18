//go:build integration

package verification

import (
	"context"
	"fmt"
	"math/rand/v2"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// codeIn returns the code of digits digits in body, failing t without one.
func codeIn(t *testing.T, body string, digits int) string {
	t.Helper()
	code := regexp.MustCompile(`\b\d{` + strconv.Itoa(digits) + `}\b`).FindString(body)
	if code == "" {
		t.Fatalf("no %d-digit code in %q", digits, body)
	}
	return code
}

// wrongCode returns a code of code's length that isn't code.
func wrongCode(code string) string {
	b := []byte(code)
	b[len(b)-1] = '0' + (b[len(b)-1]-'0'+1)%10
	return string(b)
}

// age moves userID's codes in table back by d, as if sent d earlier.
func age(t *testing.T, table string, userID uuid.UUID, d time.Duration) {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(context.Background(), `UPDATE account.`+table+`
		SET created_at = created_at - $2::interval, expires_at = expires_at - $2::interval WHERE user_id = $1`,
		userID, d.String()); err != nil {
		t.Fatal(err)
	}
}

// phoneNumber returns a random E.164 number.
func phoneNumber() string { return fmt.Sprintf("+1415%07d", rand.IntN(10_000_000)) }
