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

	sig, err := priv.Sign(transcript)
	if err != nil {
		t.Fatal(err)
	}

	transcript2 := merlin.NewTranscript("hello")
	ok := pub.Verify(sig, transcript2)
	if !ok {
		t.Fatalf("Failed to verify")
	}
}
