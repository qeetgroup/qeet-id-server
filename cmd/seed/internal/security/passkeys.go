package security

import (
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
)

// Passkeys are display rows: registering one takes a browser ceremony, so a
// seeded passkey can be listed, renamed and removed but not signed in with.
// Each names a real authenticator, with its AAGUID, transports and backup
// flags as that authenticator reports them.

// authenticator is a kind of passkey as its authenticator registers it.
type authenticator struct {
	name       string
	aaguid     string
	transports []string
	synced     bool // a passkey provider that backs it up (backup eligible and backed up)
	counter    bool // keeps a signature counter (security keys); synced passkeys send 0
}

var (
	iCloudKeychain = func(name string) authenticator {
		return authenticator{name, "fbfc3007-154e-4ecc-8c0b-6e020557d7bd", []string{"internal", "hybrid"}, true, false}
	}
	windowsHello          = authenticator{"Windows Hello", "08987058-cadc-4b81-b6e1-30de50dcbe96", []string{"internal"}, false, true}
	googlePasswordManager = func(name string) authenticator {
		return authenticator{name, "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4", []string{"internal", "hybrid"}, true, false}
	}
	yubiKey = authenticator{"YubiKey 5C NFC", "ee882879-721c-4913-9775-3dfcce97072a", []string{"nfc", "usb"}, false, true}
)

// desktopPasskey is the passkey a person's computer makes.
func desktopPasskey(w *world.World, d world.Device) authenticator {
	switch {
	case strings.Contains(d.Label, "macOS"):
		return iCloudKeychain(world.Pick(w, []string{"MacBook Pro (Touch ID)", "MacBook Pro (Touch ID)", "MacBook Air (Touch ID)"}))
	case strings.Contains(d.Label, "Windows"):
		return windowsHello
	default:
		return yubiKey
	}
}

// mobilePasskey is the passkey a person's phone or tablet makes.
func mobilePasskey(d world.Device) authenticator {
	switch {
	case strings.Contains(d.UserAgent, "iPad"):
		return iCloudKeychain("iPad")
	case strings.Contains(d.UserAgent, "iPhone"):
		return iCloudKeychain("iPhone")
	}
	for code, model := range androidModels {
		if strings.Contains(d.UserAgent, code) {
			return googlePasswordManager(model)
		}
	}
	return googlePasswordManager("Android phone")
}

// showcasePasskeys are the passkeys of the test account that demonstrates the
// passkeys screen; it signs in with its authenticator app, as passkeys can't
// be seeded usable.
var showcasePasskeys = map[string][]authenticator{
	"aarav@qeet.in": {iCloudKeychain("MacBook Pro (Touch ID)"), yubiKey, iCloudKeychain("iPhone")},
}

// addPasskeys registers p's passkeys: one from their computer, often one from
// their phone, and a security key as a backup for security staff.
func addPasskeys(w *world.World, b *pgx.Batch, p *world.Person) {
	keys := []authenticator{desktopPasskey(w, p.Device)}
	if w.Chance(0.45) {
		keys = append(keys, mobilePasskey(p.Mobile))
	}
	if (p.Role == world.RoleSecurity || p.Department == "Security" || p.Department == "Information Security") &&
		keys[0].name != yubiKey.name {
		keys = append(keys, yubiKey)
	}
	if fixed, ok := showcasePasskeys[p.Email]; ok {
		keys = fixed
	}
	at := p.MFASince.Add(-5 * time.Minute)
	for i, k := range keys {
		created := at
		if i > 0 {
			created = w.Between(at.Add(time.Hour), maxTime(at.Add(2*time.Hour), lastSeen(w, p, at.Add(2*time.Hour))))
		}
		var used *time.Time
		if w.Chance(0.85) {
			used = ptr(lastSeen(w, p, created))
		}
		var count int64
		if k.counter && used != nil {
			count = 3 + w.Rand.Int64N(240)
		}
		b.Queue(`INSERT INTO auth.passkey_credentials
			(user_id, credential_id, public_key, sign_count, aaguid, transports, name, last_used_at, created_at,
			 backup_eligible, backup_state)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)`,
			p.ID, credentialID(w, k), coseKey(w), count, uuid.MustParse(k.aaguid), k.transports, k.name, used, created, k.synced)
	}
}

// credentialID is a random credential ID of the length k's kind issues.
func credentialID(w *world.World, k authenticator) []byte {
	n := 16
	switch {
	case k.name == yubiKey.name:
		n = 64
	case k.name == windowsHello.name:
		n = 32
	case k.synced && k.aaguid == "fbfc3007-154e-4ecc-8c0b-6e020557d7bd":
		n = 20
	}
	return randomBytes(w, n)
}

// coseKey is an ES256 public key in COSE_Key form, the shape WebAuthn stores:
// kty EC2, alg ES256, crv P-256 and the two coordinates.
func coseKey(w *world.World) []byte {
	key := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}
	key = append(key, randomBytes(w, 32)...)
	key = append(key, 0x22, 0x58, 0x20)
	return append(key, randomBytes(w, 32)...)
}

func randomBytes(w *world.World, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(w.Rand.IntN(256))
	}
	return b
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
