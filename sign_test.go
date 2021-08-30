package schnorrkel

import (
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/gtank/merlin"
	"github.com/stretchr/testify/require"
)

func ExampleSecretKey_Sign() {
	msg := []byte("hello")
	signingCtx := []byte("example")

	signingTranscript := NewSigningContext(signingCtx, msg)
	verifyTranscript := NewSigningContext(signingCtx, msg)

	priv, pub, err := GenerateKeypair()
	if err != nil {
		panic(err)
	}

	sig, err := priv.Sign(signingTranscript)
	if err != nil {
		panic(err)
	}

	ok, err := pub.Verify(sig, verifyTranscript)
	if err != nil {
		panic(err)
	}

	if !ok {
		fmt.Println("failed to verify signature")
		return
	}

	fmt.Println("verified signature")
	// Output: verified signature
}

func ExamplePublicKey_Verify() {
	pub, err := NewPublicKeyFromHex("0x46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a")
	if err != nil {
		panic(err)
	}

	sig, err := NewSignatureFromHex("0x4e172314444b8f820bb54c22e95076f220ed25373e5c178234aa6c211d29271244b947e3ff3418ff6b45fd1df1140c8cbff69fc58ee6dc96df70936a2bb74b82")
	if err != nil {
		panic(err)
	}

	msg := []byte("this is a message")
	transcript := NewSigningContext(SigningContext, msg)
	ok, err := pub.Verify(sig, transcript)
	if err != nil {
		panic(err)
	}

	if !ok {
		fmt.Println("failed to verify signature")
		return
	}

	fmt.Println("verified signature")
	// Output: verified signature
}

func ExampleSignature() {
	msg := []byte("hello")
	signingCtx := []byte("example")

	signingTranscript := NewSigningContext(signingCtx, msg)

	sk, _, err := GenerateKeypair()
	if err != nil {
		panic(err)
	}

	sig, err := sk.Sign(signingTranscript)
	if err != nil {
		panic(err)
	}

	fmt.Printf("0x%x", sig.Encode())
}

func TestSignAndVerify(t *testing.T) {
	transcript := merlin.NewTranscript("hello")
	priv, pub, err := GenerateKeypair()
	require.NoError(t, err)

	sig, err := priv.Sign(transcript)
	require.NoError(t, err)

	transcript2 := merlin.NewTranscript("hello")
	ok, err := pub.Verify(sig, transcript2)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestVerify(t *testing.T) {
	transcript := merlin.NewTranscript("hello")
	priv, pub, err := GenerateKeypair()
	require.NoError(t, err)

	sig, err := priv.Sign(transcript)
	require.NoError(t, err)

	transcript2 := merlin.NewTranscript("hello")
	ok, err := pub.Verify(sig, transcript2)
	require.NoError(t, err)
	require.True(t, ok)

	transcript3 := merlin.NewTranscript("hello")
	ok, err = pub.Verify(sig, transcript3)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestSignature_EncodeAndDecode(t *testing.T) {
	transcript := merlin.NewTranscript("hello")
	priv, _, err := GenerateKeypair()
	require.NoError(t, err)

	sig, err := priv.Sign(transcript)
	require.NoError(t, err)

	enc := sig.Encode()

	res := &Signature{}
	err = res.Decode(enc)
	require.NoError(t, err)

	s_exp := sig.s.Encode([]byte{})
	s_res := res.s.Encode([]byte{})

	r_exp := sig.r.Encode([]byte{})
	r_res := res.r.Encode([]byte{})

	require.Equal(t, s_exp, s_res)
	require.Equal(t, r_exp, r_res)
}

var SigningContext = []byte("substrate")

func TestVerify_rust(t *testing.T) {
	// test vectors from https://github.com/Warchant/sr25519-crust/blob/master/test/ds.cpp#L48
	pubhex, err := hex.DecodeString("46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a")
	require.NoError(t, err)

	in := [32]byte{}
	copy(in[:], pubhex)

	pub := &PublicKey{}
	err = pub.Decode(in)
	require.NoError(t, err)

	msg := []byte("this is a message")
	sighex, err := hex.DecodeString("4e172314444b8f820bb54c22e95076f220ed25373e5c178234aa6c211d29271244b947e3ff3418ff6b45fd1df1140c8cbff69fc58ee6dc96df70936a2bb74b82")
	require.NoError(t, err)

	sigin := [64]byte{}
	copy(sigin[:], sighex)

	sig := &Signature{}
	err = sig.Decode(sigin)
	require.NoError(t, err)

	transcript := NewSigningContext(SigningContext, msg)
	ok, err := pub.Verify(sig, transcript)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestVerify_PublicKeyAtInfinity(t *testing.T) {
	transcript := merlin.NewTranscript("hello")
	priv := SecretKey{}
	pub, err := priv.Public()
	require.NoError(t, err)
	require.Equal(t, pub.key, publicKeyAtInfinity)

	sig, err := priv.Sign(transcript)
	require.NoError(t, err)

	transcript2 := merlin.NewTranscript("hello")
	_, err = pub.Verify(sig, transcript2)
	require.True(t, errors.Is(err, errPublicKeyAtInfinity))
}
