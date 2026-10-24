package password

import "testing"

// TestVerifySecret checks that a machine secret verifies against its SHA-256
// hash and not another's, and that an Argon2id hash from before verifies once
// and asks to be replaced.
func TestVerifySecret(t *testing.T) {
	hash := HashSecret("qk_secret")
	if ok, rehash := VerifySecret(hash, "qk_secret"); !ok || rehash {
		t.Errorf("the secret against its hash: ok %v, rehash %v; want ok, no rehash", ok, rehash)
	}
	if ok, _ := VerifySecret(hash, "qk_other"); ok {
		t.Error("another secret verified")
	}
	legacy, err := Hash("qk_secret")
	if err != nil {
		t.Fatal(err)
	}
	if ok, rehash := VerifySecret(legacy, "qk_secret"); !ok || !rehash {
		t.Errorf("the secret against an Argon2id hash: ok %v, rehash %v; want both", ok, rehash)
	}
	if ok, rehash := VerifySecret(legacy, "qk_other"); ok || rehash {
		t.Errorf("another secret against an Argon2id hash: ok %v, rehash %v; want neither", ok, rehash)
	}
}
