package schnorrkel

import (
	"crypto/rand"
	"crypto/sha512"

	r255 "github.com/noot/ristretto255"
)

// MiniSecretKey is a secret scalar
type MiniSecretKey struct {
	key *r255.Scalar
}

// SecretKey consists of a secret scalar and a signing nonce
type SecretKey struct {
	key   [32]byte
	nonce [32]byte
}

// PublicKey is a member 
type PublicKey struct {
	key *r255.Element
}

// order of the ristretto255 group
// var order = [4]uint64{0x5812631a5cf5d3ed, 0x14def9dea2f79cd6, 0, 0x1000000000000000}

// GenerateKeypair generates a new schnorrkel secret key and public key
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

// NewMiniSecretKey derives a mini secret key from a byte array
func NewMiniSecretKey(b [64]byte) *MiniSecretKey {
	s := r255.NewScalar()
	s.FromUniformBytes(b[:])
	return &MiniSecretKey{key: s}
}

// NewMiniSecretKeyFromRaw derives a mini secret key from little-endian encoded raw bytes.
func NewMiniSecretKeyFromRaw(b [32]byte) (*MiniSecretKey, error) {
	s := r255.NewScalar()
	err := s.Decode(b[:])
	if err != nil {
		return nil, err
	}

	s.Reduce()

	return &MiniSecretKey{key: s}, nil
}

// NewRandomMiniSecretKey generates a mini secret key from random
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

// ExpandEd25519 expands a mini secret key into a secret key 
// https://github.com/w3f/schnorrkel/blob/43f7fc00724edd1ef53d5ae13d82d240ed6202d5/src/keys.rs#L196
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

// Public gets the public key corresponding to this mini secret key
func (s *MiniSecretKey) Public() *PublicKey {
	e := r255.NewElement()
	return &PublicKey{key: e.ScalarBaseMult(s.key)}
}

// Public gets the public key corresponding to this secret key
func (s *SecretKey) Public() (*PublicKey, error) {
	e := r255.NewElement()
	sc, err := NewMiniSecretKeyFromRaw(s.key)
	if err != nil {
		return nil, err
	}
	return &PublicKey{key: e.ScalarBaseMult(sc.key)}, nil
}

// Compress returns the encoding of the point underlying the public key
func (p *PublicKey) Compress() [32]byte {
	b := p.key.Encode([]byte{})
	enc := [32]byte{}
	copy(enc[:], b)
	return enc
}

func NewRandomElement() (*r255.Element, error) {
	e := r255.NewElement()
	s := [64]byte{}
	_, err := rand.Read(s[:])
	if err != nil {
		return nil, err
	}

	return e.FromUniformBytes(s[:]), nil
}

func NewRandomScalar() (*r255.Scalar, error) {
	s := [64]byte{}
	_, err := rand.Read(s[:])
	if err != nil {
		return nil, err
	}

	ss := r255.NewScalar()
	return ss.FromUniformBytes(s[:]), nil
}

func ScalarFromBytes(b [32]byte) (*r255.Scalar, error) {
	s := r255.NewScalar()
	err := s.Decode(b[:])
	if err != nil {
		return nil, err
	}

	s.Reduce()
	return s, nil
}