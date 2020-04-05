package schnorrkel

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/gtank/merlin"
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

func TestVerify(t *testing.T) {
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

	transcript3 := merlin.NewTranscript("hello")
	ok = pub.Verify(sig, transcript3)
	if !ok {
		t.Fatalf("Failed to verify twice")
	}
}

func TestSignature_EncodeAndDecode(t *testing.T) {
	transcript := merlin.NewTranscript("hello")
	priv, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	sig, err := priv.Sign(transcript)
	if err != nil {
		t.Fatal(err)
	}

	enc := sig.Encode()

	res := &Signature{}
	err = res.Decode(enc)
	if err != nil {
		t.Fatal(err)
	}

	s_exp := sig.S.Encode([]byte{})
	s_res := res.S.Encode([]byte{})

	r_exp := sig.R.Encode([]byte{})
	r_res := res.R.Encode([]byte{})

	if !bytes.Equal(s_exp, s_res) {
		t.Fatalf("Fail: got %v expected %v", s_res, s_exp)
	}

	if !bytes.Equal(r_exp, r_res) {
		t.Fatalf("Fail: got %v expected %v", r_res, r_exp)
	}
}

var SigningContext = []byte("substrate")

func TestVerify_rust(t *testing.T) {
	// test vectors from https://github.com/Warchant/sr25519-crust/blob/master/test/ds.cpp#L48
	pubhex, err := hex.DecodeString("46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a")
	if err != nil {
		t.Fatal(err)
	}

	in := [32]byte{}
	copy(in[:], pubhex)

	pub := &PublicKey{}
	err = pub.Decode(in)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("this is a message")
	sighex, err := hex.DecodeString("4e172314444b8f820bb54c22e95076f220ed25373e5c178234aa6c211d29271244b947e3ff3418ff6b45fd1df1140c8cbff69fc58ee6dc96df70936a2bb74b82")
	if err != nil {
		t.Fatal(err)
	}

	sigin := [64]byte{}
	copy(sigin[:], sighex)

	sig := &Signature{}
	err = sig.Decode(sigin)
	if err != nil {
		t.Fatal(err)
	}

	transcript := NewSigningContext(SigningContext, msg)
	ok := pub.Verify(sig, transcript)
	if !ok {
		t.Fatal("did not verify :(")
	}
}
