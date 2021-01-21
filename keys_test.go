package schnorrkel

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestGenerateKeypair(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	if priv == nil || pub == nil {
		t.Fatal("Fail: priv or pub is nil")
	}

	pub2, err := priv.Public()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pub2.key.Encode([]byte{}), pub.key.Encode([]byte{})) {
		t.Fatalf("Fail: public key from secret doesn't equal generated public\n%x\n%x", pub2.key.Encode([]byte{}), pub.key.Encode([]byte{}))
	}
}

// test cases from: https://github.com/Warchant/sr25519-crust/blob/master/test/keypair_from_seed.cpp
func TestMiniSecretKey_ExpandEd25519(t *testing.T) {
	msc, err := NewMiniSecretKeyFromRaw([32]byte{})
	if err != nil {
		t.Fatal(err)
	}

	sc := msc.ExpandEd25519()

	expected, err := hex.DecodeString("caa835781b15c7706f65b71f7a58c807ab360faed6440fb23e0f4c52e930de0a0a6a85eaa642dac835424b5d7c8d637c00408c7a73da672b7f498521420b6dd3def12e42f3e487e9b14095aa8d5cc16a33491f1b50dadcf8811d1480f3fa8627")
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(sc.key[:], expected[:32]) {
		t.Errorf("Fail to expand key: got %x expected %x", sc.key, expected[:32])
	}

	if !bytes.Equal(sc.nonce[:], expected[32:64]) {
		t.Errorf("Fail to expand nonce: got %x expected %x", sc.nonce, expected[32:64])
	}

	pub := msc.Public().Compress()
	if !bytes.Equal(pub[:], expected[64:]) {
		t.Errorf("Fail to expand nonce: got %x expected %x", sc.nonce, expected[32:64])
	}
}

func TestMiniSecretKey_Public(t *testing.T) {
	// test vectors from https://github.com/noot/schnorrkel/blob/master/src/keys.rs#L996
	raw := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2}
	msc, err := NewMiniSecretKeyFromRaw(raw)
	if err != nil {
		t.Fatal(err)
	}

	sc := msc.ExpandEd25519()
	expectedKey := []byte{11, 241, 180, 83, 213, 181, 31, 180, 138, 45, 144, 84, 2, 78, 47, 81, 225, 208, 202, 53, 128, 52, 89, 144, 36, 92, 197, 51, 166, 28, 152, 10}
	expectedNonce := []byte{69, 121, 245, 84, 53, 88, 241, 101, 252, 126, 198, 17, 237, 114, 215, 135, 224, 58, 4, 75, 134, 169, 226, 109, 76, 133, 25, 135, 115, 81, 176, 46}
	expectedPubkey := []byte{140, 122, 228, 195, 50, 29, 229, 250, 94, 159, 183, 123, 208, 116, 7, 78, 229, 29, 247, 64, 172, 187, 92, 144, 121, 56, 242, 3, 116, 99, 100, 32}

	if !bytes.Equal(sc.key[:], expectedKey) {
		t.Errorf("Fail to expand key: got %x expected %x", sc.key, expectedKey)
	}

	if !bytes.Equal(sc.nonce[:], expectedNonce) {
		t.Errorf("Fail to expand nonce: got %x expected %x", sc.nonce, expectedNonce)
	}

	pub := msc.Public().Compress()
	if !bytes.Equal(pub[:], expectedPubkey) {
		t.Errorf("Fail to expand pubkey: got %x expected %x", pub, expectedPubkey)
	}

}

func TestPublicKey_Decode(t *testing.T) {
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

	privhex, err := hex.DecodeString("05d65584630d16cd4af6d0bec10f34bb504a5dcb62dba2122d49f5a663763d0a")
	if err != nil {
		t.Fatal(err)
	}

	copy(in[:], privhex)
	priv := &SecretKey{}
	err = priv.Decode(in)
	if err != nil {
		t.Fatal(err)
	}

	expected, err := priv.Public()
	if err != nil {
		t.Fatal(err)
	}

	pubcmp := pub.Compress()
	expcmp := expected.Compress()
	if !bytes.Equal(pubcmp[:], expcmp[:]) {
		t.Fatalf("Fail: got %x expected %x", pubcmp, expcmp)
	}
}

func TestNewPublicKey(t *testing.T) {
	pub := [32]byte{140, 122, 228, 195, 50, 29, 229, 250, 94, 159, 183, 123, 208, 116, 7, 78, 229, 29, 247, 64, 172, 187, 92, 144, 121, 56, 242, 3, 116, 99, 100, 32}
	pk := NewPublicKey(pub)
	enc := pk.Encode()
	if !bytes.Equal(enc[:], pub[:]) {
		t.Fatalf("Fail: got %x expected %x", pub, enc)
	}
}
