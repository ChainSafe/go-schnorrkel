package schnorrkel

import (
	"testing"
)

func TestGenerateKeypair(t *testing.T) {
	priv, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	if !scMinimal(priv[:]) {
		t.Fatalf("invalid private key: got %x", priv)
	}
}
