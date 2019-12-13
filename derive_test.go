package schnorrkel

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/blake2b"
)

func TestDeriveKey(t *testing.T) {
	priv, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	transcript := NewSigningContext([]byte("test"), []byte("noot"))
	msg := []byte("hello")
	cc := blake2b.Sum256(msg)
	_, err = priv.DeriveKey(transcript, cc)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDerivePublicAndPrivateMatch(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	transcriptPriv := NewSigningContext([]byte("test"), []byte("noot"))
	transcriptPub := NewSigningContext([]byte("test"), []byte("noot"))
	msg := []byte("hello")
	cc := blake2b.Sum256(msg)

	dpriv, err := priv.DeriveKey(transcriptPriv, cc)
	if err != nil {
		t.Fatal(err)
	}

	// confirm chain codes are the same for private and public paths
	dpub, _ := pub.DeriveKey(transcriptPub, cc)
	if !bytes.Equal(dpriv.chaincode[:], dpub.chaincode[:]) {
		t.Fatalf("Fail: chaincodes do not match: pub.chaincode %x priv.chaincode %x", dpub.chaincode, dpriv.chaincode)
	}

	dpub2, err := dpriv.key.(*SecretKey).Public()
	if err != nil {
		t.Fatal(err)
	}

	pubbytes := dpub.key.Encode()
	pubFromPrivBytes := dpub2.Encode()

	// confirm public keys are the same from private and public paths
	if !bytes.Equal(pubbytes[:], pubFromPrivBytes[:]) {
		t.Fatalf("Fail: public key mismatch: pub %x pub from priv %x", pubbytes, pubFromPrivBytes)
	}

	signingTranscript := NewSigningContext([]byte("test"), []byte("signme"))
	verifyTranscript := NewSigningContext([]byte("test"), []byte("signme"))
	sig, err := dpriv.key.(*SecretKey).Sign(signingTranscript)
	if err != nil {
		t.Fatal(err)
	}

	// confirm that key derived from public path can verify signature derived from private path
	ok := dpub.key.(*PublicKey).Verify(sig, verifyTranscript)
	if !ok {
		t.Fatal("did not verify")
	}
}
