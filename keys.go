package schnorrkel

import (
	"crypto/rand"
	"crypto/sha512"

	r255 "github.com/gtank/ristretto255"
)

// a member of the ristretto255 group, size = 32 bytes
type MiniSecretKey struct {
	key *r255.Scalar
}

type SecretKey struct {
	key   [32]byte
	nonce [32]byte
}

type PublicKey struct {
	key *r255.Element
}

// order of the ristretto255 group
// var order = [4]uint64{0x5812631a5cf5d3ed, 0x14def9dea2f79cd6, 0, 0x1000000000000000}

// derive a mini secret key from a byte array
func NewMiniSecretKey(b [64]byte) *MiniSecretKey {
	s := r255.NewScalar()
	s.FromUniformBytes(b[:])
	return &MiniSecretKey{key: s}
}

// derive a mini secret key from little-endian encoded raw bytes.
// will error if b is not less than curve order. TODO: perform b mod l
func NewMiniSecretKeyFromRaw(b [32]byte) (*MiniSecretKey, error) {
	s := r255.NewScalar()
	err := s.Decode(b[:])
	if err != nil {
		return nil, err
	}

	return &MiniSecretKey{key: s}, nil
}

// generate a mini secret key from random
func NewRandomMiniSecretKey() (*MiniSecretKey, error) {
	s := [64]byte{}
	_, err := rand.Read(s[:])
	if err != nil {
		return nil, err
	}

	scpriv := r255.NewScalar()
	scpriv.FromUniformBytes(s[:])
	return &MiniSecretKey{key: scpriv}, nil
}

// expand a mini secret key into
func (s *MiniSecretKey) ExpandEd25519() *SecretKey {
	h := sha512.Sum512(s.key.Encode([]byte{}))
	sk := &SecretKey{key: [32]byte{}, nonce: [32]byte{}}

	copy(sk.key[:], h[:32])
	sk.key[0] &= 248
	sk.key[31] &= 63
	sk.key[31] |= 64
	t := divideScalarByCofactor(sk.key[:])
	copy(sk.key[:], t)

	copy(sk.nonce[:], h[32:])

	return sk
}

func (s *MiniSecretKey) Public() *PublicKey {
	e := r255.NewElement()
	return &PublicKey{key: e.ScalarBaseMult(s.key)}
}

func GenerateKeypair() (*SecretKey, *PublicKey, error) {
	s := [64]byte{}
	_, err := rand.Read(s[:])
	if err != nil {
		return nil, nil, err
	}

	// decodes priv bytes as little-endian
	scpriv := r255.NewScalar()
	scpriv.FromUniformBytes(s[:])

	msc := &MiniSecretKey{key: scpriv}
	return msc.ExpandEd25519(), msc.Public(), nil
}
