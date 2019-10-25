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
	t.Logf("%x", pub)
}

func TestMiniSecretKey_Public(t *testing.T) {
	raw := [32]byte{1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2}
	msc, err := NewMiniSecretKeyFromRaw(raw)
	if err != nil {
		t.Fatal(err)
	}

	sc := msc.ExpandEd25519()
	expected, err := hex.DecodeString("1ec20c6cb85bf4c7423b95752b70c312e6ae9e5701ffb310f0a9019d9c041e0af98d66f39442506ff947fd911f18c7a7a5da639a63e8d3b4e233f74143d951c1741c08a06f41c596608f6774259bd9043304adfa5d3eea62760bd9be97634d63")
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
	t.Logf("%x", pub)
}
