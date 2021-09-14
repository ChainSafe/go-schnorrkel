package schnorrkel

import (
	"errors"
	"fmt"
	"testing"

	"github.com/gtank/merlin"
	r255 "github.com/gtank/ristretto255"
	"github.com/stretchr/testify/require"
)

func ExampleSecretKey_VrfSign() {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		panic(err)
	}

	signTranscript := merlin.NewTranscript("vrf-test")
	verifyTranscript := merlin.NewTranscript("vrf-test")

	inout, proof, err := priv.VrfSign(signTranscript)
	if err != nil {
		panic(err)
	}

	ok, err := pub.VrfVerify(verifyTranscript, inout.Output(), proof)
	if err != nil {
		panic(err)
	}

	if !ok {
		fmt.Println("failed to verify VRF output and proof")
		return
	}

	fmt.Println("verified VRF output and proof")
	// Output: verified VRF output and proof
}

func TestInputAndOutput(t *testing.T) {
	signTranscript := merlin.NewTranscript("vrf-test")
	verifyTranscript := merlin.NewTranscript("vrf-test")

	priv, pub, err := GenerateKeypair()
	require.NoError(t, err)

	inout, proof, err := priv.VrfSign(signTranscript)
	require.NoError(t, err)

	outslice := inout.output.Encode([]byte{})
	outbytes := [32]byte{}
	copy(outbytes[:], outslice)
	out, err := NewOutput(outbytes)
	require.NoError(t, err)

	ok, err := pub.VrfVerify(verifyTranscript, out, proof)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestOutput_EncodeAndDecode(t *testing.T) {
	o, err := NewRandomElement()
	require.NoError(t, err)

	out := &VrfOutput{
		output: o,
	}

	enc := out.Encode()
	out2 := new(VrfOutput)
	err = out2.Decode(enc)
	require.NoError(t, err)

	enc2 := out2.Encode()
	require.Equal(t, enc[:], enc2[:])
}

func TestProof_EncodeAndDecode(t *testing.T) {
	c, err := NewRandomScalar()
	require.NoError(t, err)

	s, err := NewRandomScalar()
	require.NoError(t, err)

	proof := &VrfProof{
		c: c,
		s: s,
	}

	enc := proof.Encode()
	proof2 := new(VrfProof)
	err = proof2.Decode(enc)
	require.NoError(t, err)

	enc2 := proof2.Encode()
	require.Equal(t, enc[:], enc2[:])
}

func TestVRFSignAndVerify(t *testing.T) {
	signTranscript := merlin.NewTranscript("vrf-test")
	verifyTranscript := merlin.NewTranscript("vrf-test")
	verify2Transcript := merlin.NewTranscript("vrf-test")

	priv, pub, err := GenerateKeypair()
	require.NoError(t, err)

	inout, proof, err := priv.VrfSign(signTranscript)
	require.NoError(t, err)

	ok, err := pub.VrfVerify(verifyTranscript, inout.Output(), proof)
	require.NoError(t, err)
	require.True(t, ok)

	proof.c, err = NewRandomScalar()
	require.NoError(t, err)

	ok, err = pub.VrfVerify(verify2Transcript, inout.Output(), proof)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestVrfVerify_rust(t *testing.T) {
	// test case from https://github.com/w3f/schnorrkel/blob/798ab3e0813aa478b520c5cf6dc6e02fd4e07f0a/src/vrf.rs#L922
	pubbytes := [32]byte{192, 42, 72, 186, 20, 11, 83, 150, 245, 69, 168, 222, 22, 166, 167, 95, 125, 248, 184, 67, 197, 10, 161, 107, 205, 116, 143, 164, 143, 127, 166, 84}
	pub, err := NewPublicKey(pubbytes)
	require.NoError(t, err)

	transcript := NewSigningContext([]byte("yo!"), []byte("meow"))

	inputbytes := []byte{56, 52, 39, 115, 143, 80, 43, 66, 174, 177, 101, 21, 177, 15, 199, 228, 180, 110, 208, 139, 229, 146, 24, 231, 118, 175, 180, 55, 191, 37, 150, 61}
	outputbytes := []byte{0, 91, 50, 25, 214, 94, 119, 36, 71, 216, 33, 152, 85, 184, 34, 120, 61, 161, 164, 223, 76, 53, 40, 246, 76, 38, 235, 204, 43, 31, 179, 28}
	input := r255.NewElement()
	err = input.Decode(inputbytes)
	require.NoError(t, err)

	output := r255.NewElement()
	err = output.Decode(outputbytes)
	require.NoError(t, err)

	inout := &VrfInOut{
		input:  input,
		output: output,
	}

	cbytes := []byte{120, 23, 235, 159, 115, 122, 207, 206, 123, 232, 75, 243, 115, 255, 131, 181, 219, 241, 200, 206, 21, 22, 238, 16, 68, 49, 86, 99, 76, 139, 39, 0}
	sbytes := []byte{102, 106, 181, 136, 97, 141, 187, 1, 234, 183, 241, 28, 27, 229, 133, 8, 32, 246, 245, 206, 199, 142, 134, 124, 226, 217, 95, 30, 176, 246, 5, 3}
	c := r255.NewScalar()
	err = c.Decode(cbytes)
	require.NoError(t, err)

	s := r255.NewScalar()
	err = s.Decode(sbytes)
	require.NoError(t, err)

	proof := &VrfProof{
		c: c,
		s: s,
	}

	ok, err := pub.VrfVerify(transcript, inout.Output(), proof)
	require.NoError(t, err)
	require.True(t, ok)
}

// input data from https://github.com/noot/schnorrkel/blob/master/src/vrf.rs#L922
func TestVrfInOut_MakeBytes(t *testing.T) {
	transcript := NewSigningContext([]byte("yo!"), []byte("meow"))

	pub := [32]byte{12, 132, 183, 11, 234, 190, 96, 172, 111, 239, 163, 137, 148, 163, 69, 79, 230, 61, 134, 41, 69, 90, 134, 229, 132, 128, 6, 63, 139, 220, 202, 0}
	input := []byte{188, 162, 182, 161, 195, 26, 55, 223, 166, 205, 136, 92, 211, 130, 184, 194, 183, 81, 215, 192, 168, 12, 39, 55, 218, 165, 8, 105, 155, 73, 128, 68}
	output := [32]byte{214, 40, 153, 246, 88, 74, 127, 242, 54, 193, 7, 5, 90, 51, 45, 5, 207, 59, 64, 68, 134, 232, 19, 223, 249, 88, 74, 125, 64, 74, 220, 48}
	proof := [64]byte{144, 199, 179, 5, 250, 199, 220, 177, 12, 220, 242, 196, 168, 237, 106, 3, 62, 195, 74, 127, 134, 107, 137, 91, 165, 104, 223, 244, 3, 4, 141, 10, 129, 54, 134, 31, 49, 250, 205, 203, 254, 142, 87, 123, 216, 108, 190, 112, 204, 204, 188, 30, 84, 36, 247, 217, 59, 125, 45, 56, 112, 195, 84, 15}
	make_bytes_16_expected := []byte{169, 57, 149, 50, 0, 243, 120, 138, 25, 250, 74, 235, 247, 137, 228, 40}

	pubkey, err := NewPublicKey(pub)
	require.NoError(t, err)

	out := new(VrfOutput)
	err = out.Decode(output)
	require.NoError(t, err)

	inout, err := out.AttachInput(pubkey, transcript)
	require.NoError(t, err)
	require.Equal(t, input, inout.input.Encode([]byte{}))

	p := new(VrfProof)
	err = p.Decode(proof)
	require.NoError(t, err)

	verifyTranscript := NewSigningContext([]byte("yo!"), []byte("meow"))
	ok, err := pubkey.VrfVerify(verifyTranscript, out, p)
	require.NoError(t, err)
	require.True(t, ok)

	bytes, err := inout.MakeBytes(16, []byte("substrate-babe-vrf"))
	require.NoError(t, err)
	require.Equal(t, make_bytes_16_expected, bytes)
}

func TestVrfVerify_NotKusama(t *testing.T) {
	kusamaVRF = false
	defer func() {
		kusamaVRF = true
	}()

	transcript := NewSigningContext([]byte("yo!"), []byte("meow"))
	pub := [32]byte{178, 10, 148, 176, 134, 205, 129, 139, 45, 90, 42, 14, 71, 116, 227, 233, 15, 253, 56, 53, 123, 7, 89, 240, 129, 61, 83, 213, 88, 73, 45, 111}
	input := []byte{118, 192, 145, 134, 145, 226, 209, 28, 62, 15, 187, 236, 43, 229, 255, 161, 72, 122, 128, 21, 28, 155, 72, 19, 67, 100, 50, 217, 72, 35, 95, 111}
	output := [32]byte{114, 173, 188, 116, 143, 11, 157, 244, 87, 214, 231, 0, 234, 34, 157, 145, 62, 154, 68, 161, 121, 66, 49, 25, 123, 38, 138, 20, 207, 105, 7, 5}
	proof := [64]byte{123, 219, 60, 236, 49, 106, 113, 229, 135, 98, 153, 252, 10, 63, 65, 174, 242, 191, 130, 65, 119, 177, 227, 15, 103, 219, 192, 100, 174, 204, 136, 3, 95, 148, 246, 105, 108, 51, 20, 173, 123, 108, 5, 49, 253, 21, 170, 41, 214, 1, 141, 97, 93, 182, 52, 175, 202, 186, 149, 213, 69, 57, 7, 14}
	make_bytes_16_expected := []byte{193, 153, 104, 18, 4, 27, 121, 146, 149, 228, 12, 17, 251, 184, 117, 16}

	pubkey, err := NewPublicKey(pub)
	require.NoError(t, err)

	out := new(VrfOutput)
	err = out.Decode(output)
	require.NoError(t, err)

	inout, err := out.AttachInput(pubkey, transcript)
	require.NoError(t, err)
	require.Equal(t, input, inout.input.Encode([]byte{}))

	p := new(VrfProof)
	err = p.Decode(proof)
	require.NoError(t, err)

	verifyTranscript := NewSigningContext([]byte("yo!"), []byte("meow"))
	ok, err := pubkey.VrfVerify(verifyTranscript, out, p)
	require.NoError(t, err)
	require.True(t, ok)

	bytes, err := inout.MakeBytes(16, []byte("substrate-babe-vrf"))
	require.NoError(t, err)
	require.Equal(t, make_bytes_16_expected, bytes)
}

func TestVRFVerify_PublicKeyAtInfinity(t *testing.T) {
	signTranscript := merlin.NewTranscript("vrf-test")
	verifyTranscript := merlin.NewTranscript("vrf-test")

	priv := SecretKey{}
	pub, err := priv.Public()
	require.NoError(t, err)
	require.Equal(t, pub.key, publicKeyAtInfinity)
	inout, proof, err := priv.VrfSign(signTranscript)
	require.NoError(t, err)

	_, err = pub.VrfVerify(verifyTranscript, inout.Output(), proof)
	require.True(t, errors.Is(err, errPublicKeyAtInfinity))
}
