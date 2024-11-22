package schnorrkel_test

import (
	"fmt"

	"github.com/ChainSafe/go-schnorrkel"
	"github.com/gtank/merlin"
)

func ExampleMiniSecretKey() {
	// To create a private-public keypair from a subkey keypair, use `NewMiniSecretKeyFromRaw`
	// This example uses the substrate built-in key Alice:
	// $ subkey inspect //Alice
	priv, err := schnorrkel.NewMiniSecretKeyFromHex("0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a")
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

	signingTranscript := schnorrkel.NewSigningContext(signingCtx, msg)

	msk, err := schnorrkel.NewMiniSecretKeyFromHex("0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a")
	if err != nil {
		panic(err)
	}

	sk := msk.ExpandEd25519()

	_, err = sk.Sign(signingTranscript)
	if err != nil {
		panic(err)
	}

	fmt.Println("expanded private key")
	// Output: expanded private key
}

func ExampleGenerateKeypair() {
	priv, pub, err := schnorrkel.GenerateKeypair()
	if err != nil {
		panic(err)
	}

	privStr := fmt.Sprintf("0x%x", priv.Encode())
	pubStr := fmt.Sprintf("0x%x", pub.Encode())
	_, err = schnorrkel.NewMiniSecretKeyFromHex(privStr)
	if err != nil {
		fmt.Printf("failed to decode private key, %v\n", err)
		return
	}
	_, err = schnorrkel.NewPublicKeyFromHex(pubStr)
	if err != nil {
		fmt.Printf("failed to decode public key, %v\n", err)
		return
	}
	fmt.Println("example keypair")
	// Output: example keypair
}

func ExampleSignature() {
	msg := []byte("hello")
	signingCtx := []byte("example")

	signingTranscript := schnorrkel.NewSigningContext(signingCtx, msg)

	sk, _, err := schnorrkel.GenerateKeypair()
	if err != nil {
		panic(err)
	}

	sig, err := sk.Sign(signingTranscript)
	if err != nil {
		panic(err)
	}

	encoded := fmt.Sprintf("0x%x", sig.Encode())

	_, err = schnorrkel.NewSignatureFromHex(encoded)
	if err != nil {
		fmt.Println("failed to decode signature")
		return
	}
	fmt.Println("example signature")
	// Output: example signature
}

func ExampleSecretKey_VrfSign() {
	priv, pub, err := schnorrkel.GenerateKeypair()
	if err != nil {
		panic(err)
	}

	signTranscript := merlin.NewTranscript("vrf-test")
	verifyTranscript := merlin.NewTranscript("vrf-test")

	inout, proof, err := priv.VrfSign(signTranscript)
	if err != nil {
		panic(err)
	}

	ok, err := pub.VrfVerify(verifyTranscript, inout.Output(), proof)
	if err != nil {
		panic(err)
	}

	if !ok {
		fmt.Println("failed to verify VRF output and proof")
		return
	}

	fmt.Println("verified VRF output and proof")
	// Output: verified VRF output and proof
}

func ExampleKeypair_VrfSign() {
	priv, pub, err := schnorrkel.GenerateKeypair()
	if err != nil {
		panic(err)
	}

	kp := schnorrkel.NewKeypair(pub, priv)

	signTranscript := merlin.NewTranscript("vrf-test")
	verifyTranscript := merlin.NewTranscript("vrf-test")

	inout, proof, err := kp.VrfSign(signTranscript)
	if err != nil {
		panic(err)
	}

	ok, err := kp.VrfVerify(verifyTranscript, inout.Output(), proof)
	if err != nil {
		panic(err)
	}

	if !ok {
		fmt.Println("failed to verify VRF output and proof")
		return
	}

	fmt.Println("verified VRF output and proof")
	// Output: verified VRF output and proof
}

func ExampleSecretKey_Sign() {
	msg := []byte("hello")
	signingCtx := []byte("example")

	signingTranscript := schnorrkel.NewSigningContext(signingCtx, msg)
	verifyTranscript := schnorrkel.NewSigningContext(signingCtx, msg)

	priv, pub, err := schnorrkel.GenerateKeypair()
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
	signingContext := []byte("substrate")

	pub, err := schnorrkel.NewPublicKeyFromHex("0x46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a")
	if err != nil {
		panic(err)
	}

	sig, err := schnorrkel.NewSignatureFromHex(
		"0x4e172314444b8f820bb54c22e95076f220ed25373e5c178234aa6c211d29271244b947e3ff3418ff6b45fd1df1140c8cbff69fc58ee6dc96df70936a2bb74b82")
	if err != nil {
		panic(err)
	}

	msg := []byte("this is a message")
	transcript := schnorrkel.NewSigningContext(signingContext, msg)
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

func ExampleGenerateMnemonic() {
	mnemonic, err := schnorrkel.GenerateMnemonic()
	if err != nil {
		panic(err)
	}

	_, err = schnorrkel.MiniSecretKeyFromMnemonic(mnemonic, "")
	if err != nil {
		panic(err)
	}

	fmt.Println("generated mnemonic")
	// Output: generated mnemonic
}

func ExampleMiniSecretKeyFromMnemonic() {
	mnemonic := "legal winner thank year wave sausage worth useful legal winner thank yellow"
	msk, err := schnorrkel.MiniSecretKeyFromMnemonic(mnemonic, "Substrate")
	if err != nil {
		panic(err)
	}

	fmt.Printf("0x%x", msk.Encode())
	// Output: 0x4313249608fe8ac10fd5886c92c4579007272cb77c21551ee5b8d60b78041685
}
