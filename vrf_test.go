package schnorrkel

import (
	"bytes"
	"testing"

	"github.com/gtank/merlin"
	r255 "github.com/gtank/ristretto255"
)

func TestInputAndOutput(t *testing.T) {
	signTranscript := merlin.NewTranscript("vrf-test")
	inoutTranscript := merlin.NewTranscript("vrf-test")
	verifyTranscript := merlin.NewTranscript("vrf-test")

	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	inout, proof, err := priv.VrfSign(signTranscript)
	if err != nil {
		t.Fatal(err)
	}

	outslice := inout.output.Encode([]byte{})
	outbytes := [32]byte{}
	copy(outbytes[:], outslice)
	out := NewOutput(outbytes)
	inout2 := out.AttachInput(pub, inoutTranscript)

	ok, err := pub.VrfVerify(verifyTranscript, inout2, proof)
	if err != nil {
		t.Fatal(err)
	}

	if !ok {
		t.Fatal("did not verify vrf")
	}
}

func TestOutput_EncodeAndDecode(t *testing.T) {
	o, err := NewRandomElement()
	if err != nil {
		t.Fatal(err)
	}
	out := &VrfOutput{
		output: o,
	}

	enc := out.Encode()
	out2 := new(VrfOutput)
	err = out2.Decode(enc)
	if err != nil {
		t.Fatal(err)
	}
	enc2 := out2.Encode()
	if !bytes.Equal(enc[:], enc2[:]) {
		t.Fatalf("Fail: got %v expected %v", out.Encode(), out2.Encode())
	}
}

func TestProof_EncodeAndDecode(t *testing.T) {
	c, err := NewRandomScalar()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewRandomScalar()
	if err != nil {
		t.Fatal(err)
	}

	proof := &VrfProof{
		c: c,
		s: s,
	}

	enc := proof.Encode()
	proof2 := new(VrfProof)
	err = proof2.Decode(enc)
	if err != nil {
		t.Fatal(err)
	}

	enc2 := proof2.Encode()
	if !bytes.Equal(enc[:], enc2[:]) {
		t.Fatalf("Fail: got %v expected %v", proof.Encode(), proof2.Encode())
	}
}

func TestVRFSignAndVerify(t *testing.T) {
	signTranscript := merlin.NewTranscript("vrf-test")
	verifyTranscript := merlin.NewTranscript("vrf-test")
	verify2Transcript := merlin.NewTranscript("vrf-test")

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

	proof.c, err = NewRandomScalar()
	if err != nil {
		t.Fatal(err)
	}

	ok, err = pub.VrfVerify(verify2Transcript, inout, proof)
	if err != nil {
		t.Fatal(err)
	}

	if ok {
		t.Fatal("verified invalid proof")
	}
}

func TestVrfVerify_rust(t *testing.T) {
	// test case from https://github.com/w3f/schnorrkel/blob/798ab3e0813aa478b520c5cf6dc6e02fd4e07f0a/src/vrf.rs#L922
	pubbytes := [32]byte{192, 42, 72, 186, 20, 11, 83, 150, 245, 69, 168, 222, 22, 166, 167, 95, 125, 248, 184, 67, 197, 10, 161, 107, 205, 116, 143, 164, 143, 127, 166, 84}
	pub := NewPublicKey(pubbytes)

	transcript := NewSigningContext([]byte("yo!"), []byte("meow"))

	inputbytes := []byte{56, 52, 39, 115, 143, 80, 43, 66, 174, 177, 101, 21, 177, 15, 199, 228, 180, 110, 208, 139, 229, 146, 24, 231, 118, 175, 180, 55, 191, 37, 150, 61}
	outputbytes := []byte{0, 91, 50, 25, 214, 94, 119, 36, 71, 216, 33, 152, 85, 184, 34, 120, 61, 161, 164, 223, 76, 53, 40, 246, 76, 38, 235, 204, 43, 31, 179, 28}
	input := r255.NewElement()
	err := input.Decode(inputbytes)
	if err != nil {
		t.Fatal(err)
	}
	output := r255.NewElement()
	err = output.Decode(outputbytes)
	if err != nil {
		t.Fatal(err)
	}

	inout := &VrfInOut{
		input:  input,
		output: output,
	}

	cbytes := []byte{120, 23, 235, 159, 115, 122, 207, 206, 123, 232, 75, 243, 115, 255, 131, 181, 219, 241, 200, 206, 21, 22, 238, 16, 68, 49, 86, 99, 76, 139, 39, 0}
	sbytes := []byte{102, 106, 181, 136, 97, 141, 187, 1, 234, 183, 241, 28, 27, 229, 133, 8, 32, 246, 245, 206, 199, 142, 134, 124, 226, 217, 95, 30, 176, 246, 5, 3}
	c := r255.NewScalar()
	err = c.Decode(cbytes)
	if err != nil {
		t.Fatal(err)
	}

	s := r255.NewScalar()
	err = s.Decode(sbytes)
	if err != nil {
		t.Fatal(err)
	}

	proof := &VrfProof{
		c: c,
		s: s,
	}

	ok, err := pub.VrfVerify(transcript, inout, proof)
	if err != nil {
		t.Fatal(err)
	}

	if !ok {
		t.Fatal("did not verify vrf")
	}
}
