package schnorrkel

import (
	"testing"

	"github.com/noot/merlin"
)

func TestSignAndVerify(t *testing.T) {
	transcript := merlin.NewTranscript("hello")
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("pub %x", pub.key.Encode([]byte{}))

	sig, err := priv.Sign(transcript)
	if err != nil {
		t.Fatal(err)
	}

	ok := sig.Verify(pub, transcript)
	if !ok {
		t.Fatalf("Failed to verify")
	}
}
