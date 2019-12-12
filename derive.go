package schnorrkel

import (
	"crypto/rand"

	"github.com/gtank/merlin"
	r255 "github.com/gtank/ristretto255"
)

const ChainCodeLength = 32

// DerivableKey implemented DeriveKey
type DerivableKey interface {
	Encode() [32]byte
	Decode([32]byte) error
	DeriveKey(*merlin.Transcript, [32]byte) (*ExtendedKey, error)
}

// ExtendedKey consists of a DerivableKey which can be a schnorrkel public or private key
// as well as chain code
type ExtendedKey struct {
	key       DerivableKey
	chaincode [32]byte
}

// DeriveKeySimple ...
func DeriveKeySimple(key DerivableKey, i []byte, cc [32]byte) (*ExtendedKey, error) {
	t := merlin.NewTranscript("SchnorrRistrettoHDKD")
	t.AppendMessage([]byte("sign-bytes"), i)
	return key.DeriveKey(t, cc)
}

// DeriveKey derives a new secret key and chain code from an existing secret key and chain code
func (sk *SecretKey) DeriveKey(t *merlin.Transcript, cc [32]byte) (*ExtendedKey, error) {
	pub, err := sk.Public()
	if err != nil {
		return nil, err
	}

	sc, dcc := pub.DeriveScalarAndChaincode(t, cc)

	// TODO: need transcript RNG to match rust-schnorrkel
	// see: https://github.com/w3f/schnorrkel/blob/798ab3e0813aa478b520c5cf6dc6e02fd4e07f0a/src/derive.rs#L186
	nonce := [32]byte{}
	_, err = rand.Read(nonce[:])
	if err != nil {
		return nil, err
	}

	dsk, err := ScalarFromBytes(sk.key)
	if err != nil {
		return nil, err
	}

	dsk.Add(dsk, sc)

	dskBytes := [32]byte{}
	copy(dskBytes[:], dsk.Encode([]byte{}))

	skNew := &SecretKey{
		key:   dskBytes,
		nonce: nonce,
	}

	return &ExtendedKey{
		key:       skNew,
		chaincode: dcc,
	}, nil
}

func (pk *PublicKey) DeriveKey(t *merlin.Transcript, cc [32]byte) (*ExtendedKey, error) {
	return nil, nil
}

func (ek *ExtendedKey) DeriveKey(t *merlin.Transcript) (*ExtendedKey, error) {
	return nil, nil
}

// DeriveScalarAndChaincode derives a new scalar and chain code from an existing public key and chain code
func (pk *PublicKey) DeriveScalarAndChaincode(t *merlin.Transcript, cc [32]byte) (*r255.Scalar, [32]byte) {
	t.AppendMessage([]byte("chain-code"), cc[:])
	pkenc := pk.Encode()
	t.AppendMessage([]byte("public-key"), pkenc[:])

	scBytes := t.ExtractBytes([]byte("HDKD-scalar"), 64)
	sc := r255.NewScalar()
	sc.FromUniformBytes(scBytes)

	ccBytes := t.ExtractBytes([]byte("HDKD-chaincode"), 32)
	ccRes := [32]byte{}
	copy(ccRes[:], ccBytes)
	return sc, ccRes
}
