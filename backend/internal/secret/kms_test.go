package secret

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type fakeKMS struct {
	plaintext []byte
	err       error
	gotBlob   []byte
	gotKeyID  string
}

func (f *fakeKMS) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	f.gotBlob = in.CiphertextBlob
	if in.KeyId != nil {
		f.gotKeyID = *in.KeyId
	}
	if f.err != nil {
		return nil, f.err
	}
	return &kms.DecryptOutput{Plaintext: f.plaintext}, nil
}

func TestAWSKMSProvider_DataKey(t *testing.T) {
	want := bytes.Repeat([]byte{0xAB}, 32)
	fake := &fakeKMS{plaintext: want}
	p := &AWSKMSProvider{client: fake, keyID: "arn:aws:kms:...:key/abc", wrappedDEK: []byte("wrapped")}

	got, err := p.DataKey(context.Background())
	if err != nil {
		t.Fatalf("DataKey: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("data key = %x, want %x", got, want)
	}
	if !bytes.Equal(fake.gotBlob, []byte("wrapped")) {
		t.Errorf("passed blob = %q, want %q", fake.gotBlob, "wrapped")
	}
	if fake.gotKeyID != "arn:aws:kms:...:key/abc" {
		t.Errorf("passed key id = %q", fake.gotKeyID)
	}
}

func TestAWSKMSProvider_RejectsBadKeyLength(t *testing.T) {
	p := &AWSKMSProvider{client: &fakeKMS{plaintext: []byte("17-bytes---------")}, keyID: "k", wrappedDEK: []byte("w")}
	if _, err := p.DataKey(context.Background()); err == nil {
		t.Fatal("expected error for non-AES key length, got nil")
	}
}

func TestAWSKMSProvider_PropagatesDecryptError(t *testing.T) {
	p := &AWSKMSProvider{client: &fakeKMS{err: errors.New("access denied")}, keyID: "k", wrappedDEK: []byte("w")}
	if _, err := p.DataKey(context.Background()); err == nil {
		t.Fatal("expected decrypt error to propagate, got nil")
	}
}

func TestNewAWSKMSProvider_Validation(t *testing.T) {
	if _, err := NewAWSKMSProvider(context.Background(), "", []byte("w")); err == nil {
		t.Error("expected error for empty key id")
	}
	if _, err := NewAWSKMSProvider(context.Background(), "k", nil); err == nil {
		t.Error("expected error for empty wrapped DEK")
	}
}
