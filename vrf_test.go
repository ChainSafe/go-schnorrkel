package schnorrkel

import (
	"testing"

	"github.com/gtank/merlin"
)

func TestVRFSignAndVerify(t *testing.T) {
	signTranscript := merlin.NewTranscript("vrf-test")
	verifyTranscript := merlin.NewTranscript("vrf-test")

	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	inout, proof, err := priv.VrfSign(signTranscript)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := pub.VrfVerify(verifyTranscript, inout, proof)
	if err != nil {
		t.Fatal(err)
	}

	if !ok {
		t.Fatal("did not verify vrf")
	}
}
