package schnorrkel

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func ExampleGenerateKeypair() {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		panic(err)
	}

	fmt.Printf("0x%x\n", priv.Encode())
	fmt.Printf("0x%x\n", pub.Encode())
}

func ExampleMiniSecretKey() {
	// To create a private-public keypair from a subkey keypair, use `NewMiniSecretKeyFromRaw`
	// This example uses the substrate built-in key Alice:
	// $ subkey inspect //Alice
	priv, err := NewMiniSecretKeyFromHex("0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a")
	if err != nil {
		panic(err)
	}

	pub := priv.Public()
	fmt.Printf("0x%x", pub.Encode())
	// Output: 0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d
}

func ExampleMiniSecretKey_ExpandEd25519() {
	msg := []byte("hello")
	signingCtx := []byte("example")

	signingTranscript := NewSigningContext(signingCtx, msg)

	msk, err := NewMiniSecretKeyFromHex("0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a")
	if err != nil {
		panic(err)
	}

	sk := msk.ExpandEd25519()

	sig, err := sk.Sign(signingTranscript)
	if err != nil {
		panic(err)
	}

	fmt.Printf("0x%x", sig.Encode())
}

func TestGenerateKeypair(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	require.NoError(t, err)
	require.NotNil(t, priv)
	require.NotNil(t, pub)

	pub2, err := priv.Public()
	require.NoError(t, err)
	require.Equal(t, pub.key.Encode([]byte{}), pub2.key.Encode([]byte{}))
}

// test cases from: https://github.com/Warchant/sr25519-crust/blob/master/test/keypair_from_seed.cpp
func TestMiniSecretKey_ExpandEd25519(t *testing.T) {
	msc, err := NewMiniSecretKeyFromRaw([32]byte{})
	require.NoError(t, err)

	sc := msc.ExpandEd25519()

	expected, err := hex.DecodeString("caa835781b15c7706f65b71f7a58c807ab360faed6440fb23e0f4c52e930de0a0a6a85eaa642dac835424b5d7c8d637c00408c7a73da672b7f498521420b6dd3def12e42f3e487e9b14095aa8d5cc16a33491f1b50dadcf8811d1480f3fa8627")
	require.NoError(t, err)
	require.Equal(t, expected[:32], sc.key[:])
	require.Equal(t, expected[32:64], sc.nonce[:])

	pub := msc.Public().Encode()
	require.Equal(t, expected[64:], pub[:])
}

func TestMiniSecretKey_Public(t *testing.T) {
	// test vectors from https://github.com/noot/schnorrkel/blob/master/src/keys.rs#L996
	raw := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2}
	msc, err := NewMiniSecretKeyFromRaw(raw)
	require.NoError(t, err)

	sc := msc.ExpandEd25519()
	expectedKey := []byte{11, 241, 180, 83, 213, 181, 31, 180, 138, 45, 144, 84, 2, 78, 47, 81, 225, 208, 202, 53, 128, 52, 89, 144, 36, 92, 197, 51, 166, 28, 152, 10}
	expectedNonce := []byte{69, 121, 245, 84, 53, 88, 241, 101, 252, 126, 198, 17, 237, 114, 215, 135, 224, 58, 4, 75, 134, 169, 226, 109, 76, 133, 25, 135, 115, 81, 176, 46}
	expectedPubkey := []byte{140, 122, 228, 195, 50, 29, 229, 250, 94, 159, 183, 123, 208, 116, 7, 78, 229, 29, 247, 64, 172, 187, 92, 144, 121, 56, 242, 3, 116, 99, 100, 32}

	require.Equal(t, expectedKey, sc.key[:])
	require.Equal(t, expectedNonce, sc.nonce[:])

	pub := msc.Public().Encode()
	require.Equal(t, expectedPubkey, pub[:])
}

func TestPublicKey_Decode(t *testing.T) {
	// test vectors from https://github.com/Warchant/sr25519-crust/blob/master/test/ds.cpp#L48
	pubhex, err := hex.DecodeString("46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a")
	require.NoError(t, err)

	in := [32]byte{}
	copy(in[:], pubhex)

	pub := &PublicKey{}
	err = pub.Decode(in)
	require.NoError(t, err)

	privhex, err := hex.DecodeString("05d65584630d16cd4af6d0bec10f34bb504a5dcb62dba2122d49f5a663763d0a")
	require.NoError(t, err)

	copy(in[:], privhex)
	priv := &SecretKey{}
	err = priv.Decode(in)
	require.NoError(t, err)

	expected, err := priv.Public()
	require.NoError(t, err)

	pubcmp := pub.Encode()
	expcmp := expected.Encode()
	require.Equal(t, expcmp[:], pubcmp[:])
}

func TestNewPublicKey(t *testing.T) {
	pub := [32]byte{140, 122, 228, 195, 50, 29, 229, 250, 94, 159, 183, 123, 208, 116, 7, 78, 229, 29, 247, 64, 172, 187, 92, 144, 121, 56, 242, 3, 116, 99, 100, 32}
	pk, err := NewPublicKey(pub)
	require.NoError(t, err)

	enc := pk.Encode()
	require.Equal(t, pub[:], enc[:])
}
