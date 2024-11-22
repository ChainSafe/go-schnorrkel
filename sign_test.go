package schnorrkel_test

import (
	"encoding/hex"
	"testing"

	"github.com/ChainSafe/go-schnorrkel"
	r255 "github.com/gtank/ristretto255"

	"github.com/gtank/merlin"
	"github.com/stretchr/testify/require"
)

func TestSignAndVerify(t *testing.T) {
	transcript := merlin.NewTranscript("hello")
	priv, pub, err := schnorrkel.GenerateKeypair()
	require.NoError(t, err)

	sig, err := priv.Sign(transcript)
	require.NoError(t, err)

	transcript2 := merlin.NewTranscript("hello")
	ok, err := pub.Verify(sig, transcript2)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestSignAndVerifyKeypair(t *testing.T) {
	transcript := merlin.NewTranscript("hello")
	priv, pub, err := schnorrkel.GenerateKeypair()
	require.NoError(t, err)

	kp := schnorrkel.NewKeypair(pub, priv)

	sig, err := kp.Sign(transcript)
	require.NoError(t, err)

	transcript2 := merlin.NewTranscript("hello")
	ok, err := pub.Verify(sig, transcript2)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestVerify(t *testing.T) {
	transcript := merlin.NewTranscript("hello")
	priv, pub, err := schnorrkel.GenerateKeypair()
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

func TestVerifyKeypair(t *testing.T) {
	transcript := merlin.NewTranscript("hello")
	priv, pub, err := schnorrkel.GenerateKeypair()
	require.NoError(t, err)

	kp := schnorrkel.NewKeypair(pub, priv)
	sig, err := kp.Sign(transcript)
	require.NoError(t, err)

	transcript2 := merlin.NewTranscript("hello")
	ok, err := kp.Verify(sig, transcript2)
	require.NoError(t, err)
	require.True(t, ok)

	transcript3 := merlin.NewTranscript("hello")
	ok, err = kp.Verify(sig, transcript3)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestSignature_EncodeAndDecode(t *testing.T) {
	transcript := merlin.NewTranscript("hello")
	priv, _, err := schnorrkel.GenerateKeypair()
	require.NoError(t, err)

	sig, err := priv.Sign(transcript)
	require.NoError(t, err)

	enc := sig.Encode()

	res := &schnorrkel.Signature{}
	err = res.Decode(enc)
	require.NoError(t, err)

	require.True(t, sig.Equal(res))
}

func TestVerify_rust(t *testing.T) {
	signingContext := []byte("substrate")
	// test vectors from https://github.com/Warchant/sr25519-crust/blob/master/test/ds.cpp#L48
	pubhex, err := hex.DecodeString("46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a")
	require.NoError(t, err)

	in := [32]byte{}
	copy(in[:], pubhex)

	pub := &schnorrkel.PublicKey{}
	err = pub.Decode(in)
	require.NoError(t, err)

	msg := []byte("this is a message")
	sighex, err := hex.DecodeString("4e172314444b8f820bb54c22e95076f220ed25373e5c178234aa6c211d29271244b947e3ff3418ff6b45fd1df1140c8cbff69fc58ee6dc96df70936a2bb74b82")
	require.NoError(t, err)

	sigin := [64]byte{}
	copy(sigin[:], sighex)

	sig := &schnorrkel.Signature{}
	err = sig.Decode(sigin)
	require.NoError(t, err)

	transcript := schnorrkel.NewSigningContext(signingContext, msg)
	ok, err := pub.Verify(sig, transcript)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestVerify_PublicKeyAtInfinity(t *testing.T) {
	publicKeyAtInfinity := r255.NewElement().ScalarBaseMult(r255.NewScalar())
	transcript := merlin.NewTranscript("hello")
	priv := schnorrkel.SecretKey{}
	pub, err := priv.Public()
	require.NoError(t, err)
	enc := pub.Encode()
	require.Equal(t, publicKeyAtInfinity.Encode([]byte{}), enc[:])

	sig, err := priv.Sign(transcript)
	require.NoError(t, err)

	transcript2 := merlin.NewTranscript("hello")
	_, err = pub.Verify(sig, transcript2)
	require.ErrorIs(t, err, schnorrkel.ErrPublicKeyAtInfinity)
}
