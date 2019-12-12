package schnorrkel

import (
	"testing"

	"golang.org/x/crypto/blake2b"
)

func TestDeriveKey(t *testing.T) {
	priv, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	transcript := NewSigningContext([]byte("test"), []byte("noot"))
	msg := []byte("hello")
	cc := blake2b.Sum256(msg)
	_, err = priv.DeriveKey(transcript, cc)
	if err != nil {
		t.Fatal(err)
	}
}
