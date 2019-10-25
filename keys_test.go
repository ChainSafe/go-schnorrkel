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
}

// test cases from: https://github.com/Warchant/sr25519-crust/blob/master/test/keypair_from_seed.cpp
func TestMiniSecretKey_ExpandEd25519(t *testing.T) {
	msc, err := NewMiniSecretKeyFromRaw([32]byte{})
	if err != nil {
		t.Fatal(err)
	}

	sc := msc.ExpandEd25519()

	expectedNonce, err := hex.DecodeString("0a6a85eaa642dac835424b5d7c8d637c00408c7a73da672b7f498521420b6dd3")
	if err != nil {
		t.Fatal(err)
	}

	expectedKey, err := hex.DecodeString("caa835781b15c7706f65b71f7a58c807ab360faed6440fb23e0f4c52e930de0a")
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(sc.key[:], expectedKey) {
		t.Errorf("Fail to expand key: got %x expected %x", sc.key, expectedKey)
	}

	if !bytes.Equal(sc.nonce[:], expectedNonce) {
		t.Errorf("Fail to expand nonce: got %x expected %x", sc.nonce, expectedNonce)
	}
}

// func TestMiniSecretKey_Public(t *testing.T) {
// 	raw, err := hex.DecodeString("fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e")
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	raw32 := [32]byte{}
// 	copy(raw32[:], raw)
// 	msc, err := NewMiniSecretKeyFromRaw(raw32)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	pub := msc.Public()
// 	t.Logf("%x", pub.key)
// }
