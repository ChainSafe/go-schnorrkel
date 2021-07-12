package schnorrkel

import (
	"encoding/hex"
	"testing"

	"github.com/gtank/merlin"
	"github.com/stretchr/testify/require"
)

func TestSignAndVerify(t *testing.T) {
	transcript := merlin.NewTranscript("hello")
	priv, pub, err := GenerateKeypair()
	require.NoError(t, err)

	sig, err := priv.Sign(transcript)
	require.NoError(t, err)

	transcript2 := merlin.NewTranscript("hello")
	ok := pub.Verify(sig, transcript2)
	require.True(t, ok)
}

func TestVerify(t *testing.T) {
	transcript := merlin.NewTranscript("hello")
	priv, pub, err := GenerateKeypair()
	require.NoError(t, err)

	sig, err := priv.Sign(transcript)
	require.NoError(t, err)

	transcript2 := merlin.NewTranscript("hello")
	ok := pub.Verify(sig, transcript2)
	require.True(t, ok)

	transcript3 := merlin.NewTranscript("hello")
	ok = pub.Verify(sig, transcript3)
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

	s_exp := sig.S.Encode([]byte{})
	s_res := res.S.Encode([]byte{})

	r_exp := sig.R.Encode([]byte{})
	r_res := res.R.Encode([]byte{})

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
	ok := pub.Verify(sig, transcript)
	require.True(t, ok)
}
