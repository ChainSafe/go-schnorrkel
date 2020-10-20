package schnorrkel

import (
	"bytes"
	"encoding/hex"
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

func TestDeriveSoft(t *testing.T) {
	// test vectors from https://github.com/Warchant/sr25519-crust/blob/master/test/derive.cpp#L32
	c := commonVectors{
		KeyPair:   "4c1250e05afcd79e74f6c035aee10248841090e009b6fd7ba6a98d5dc743250cafa4b32c608e3ee2ba624850b3f14c75841af84b16798bf1ee4a3875aa37a2cee661e416406384fe1ca091980958576d2bff7c461636e9f22c895f444905ea1f",
		ChainCode: "0c666f6f00000000000000000000000000000000000000000000000000000000",
		Public:    "b21e5aabeeb35d6a1bf76226a6c65cd897016df09ef208243e59eed2401f5357",
		Hard:      false,
	}

	deriveCommon(t, c)
}

func TestDeriveHard(t *testing.T) {
	// test vectors from https://github.com/Warchant/sr25519-crust/blob/4b167a8db2c4114561e5380e3493375df426b124/test/derive.cpp#L13
	c := commonVectors{
		KeyPair:   "4c1250e05afcd79e74f6c035aee10248841090e009b6fd7ba6a98d5dc743250cafa4b32c608e3ee2ba624850b3f14c75841af84b16798bf1ee4a3875aa37a2cee661e416406384fe1ca091980958576d2bff7c461636e9f22c895f444905ea1f",
		ChainCode: "14416c6963650000000000000000000000000000000000000000000000000000",
		Public:    "d8db757f04521a940f0237c8a1e44dfbe0b3e39af929eb2e9e257ba61b9a0a1a",
		Hard:      true,
	}

	deriveCommon(t, c)
}

// commonVectors is a struct to set the vectors used for deriving soft or hard
// keys for testing
type commonVectors struct {
	// KeyPair in the hex encoded string of a known keypair
	KeyPair string
	// ChainCode is the chain code for generating the derived key hex encoded
	ChainCode string
	// Public is the expected resulting public key of the derived key hex
	// encoded
	Public string
	// Hard indicates if the vectors are for deriving a Hard key
	Hard bool
}

// deriveCommon provides common functions for testing Soft and Hard key derivation
func deriveCommon(t *testing.T, vec commonVectors) {
	kp, err := hex.DecodeString(vec.KeyPair)
	if err != nil {
		t.Fatal(err)
	}

	cc, err := hex.DecodeString(vec.ChainCode)
	if err != nil {
		t.Fatal(err)
	}

	privBytes := [32]byte{}
	copy(privBytes[:], kp[:32])
	priv := new(SecretKey)
	err = priv.Decode(privBytes)
	if err != nil {
		t.Fatal(err)
	}

	ccBytes := [32]byte{}
	copy(ccBytes[:], cc)

	var derived *ExtendedKey

	if vec.Hard {
		derived, err = DeriveKeyHard(priv, []byte{}, ccBytes)
	} else {
		derived, err = DeriveKeySimple(priv, []byte{}, ccBytes)
	}

	if err != nil {
		t.Fatal(err)
	}

	expectedPub, err := hex.DecodeString(vec.Public)
	if err != nil {
		t.Fatal(err)
	}

	resultPub, err := derived.Public()
	if err != nil {
		t.Fatal(err)
	}

	resultPubBytes := resultPub.Encode()

	if !bytes.Equal(expectedPub, resultPubBytes[:]) {
		t.Fatalf("Fail: got %x expected %x", resultPubBytes, expectedPub)
	}
}
