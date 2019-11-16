package schnorrkel

import (
	"crypto/rand"
	"crypto/sha512"

	r255 "github.com/gtank/ristretto255"
	"github.com/noot/merlin"
)

// MiniSecretKey is a secret scalar
type MiniSecretKey struct {
	key *r255.Scalar
}

// SecretKey consists of a secret scalar and a signing nonce
type SecretKey struct {
	key   [32]byte // TODO: change this to a *r255.Scalar
	nonce [32]byte
}

// PublicKey is a member
type PublicKey struct {
	key *r255.Element
}

// GenerateKeypair generates a new schnorrkel secret key and public key
func GenerateKeypair() (*SecretKey, *PublicKey, error) {
	s := [64]byte{}
	_, err := rand.Read(s[:])
	if err != nil {
		return nil, nil, err
	}

	// decodes priv bytes as little-endian
	msc := NewMiniSecretKey(s)
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

func (s *MiniSecretKey) Decode(in [32]byte) (err error) {
	s, err = NewMiniSecretKeyFromRaw(in)
	return err
}

// ExpandUniform
func (s *MiniSecretKey) ExpandUniform() *SecretKey {
	t := merlin.NewTranscript("ExpandSecretKeys")
	t.AppendMessage([]byte("mini"), s.key.Encode([]byte{}))
	scalarBytes := t.ExtractBytes([]byte("sk"), 64)
	key := r255.NewScalar()
	key.FromUniformBytes(scalarBytes[:])
	nonce := t.ExtractBytes([]byte("no"), 32)
	key32 := [32]byte{}
	copy(key32[:], key.Encode([]byte{}))
	nonce32 := [32]byte{}
	copy(nonce32[:], nonce)
	return &SecretKey{
		key:   key32,
		nonce: nonce32,
	}
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
	sk := s.ExpandEd25519()
	skey, err := ScalarFromBytes(sk.key)
	if err != nil {
		return nil
	}
	return &PublicKey{key: e.ScalarBaseMult(skey)}
}

// Decode forms the secret key from the input bytes
func (s *SecretKey) Decode(in [32]byte) error {
	s.key = in
	return nil
}

// Encode returns the secret key as bytes
func (s *SecretKey) Encode() [32]byte {
	return s.key
}

// Public gets the public key corresponding to this secret key
func (s *SecretKey) Public() (*PublicKey, error) {
	e := r255.NewElement()
	sc, err := ScalarFromBytes(s.key)
	if err != nil {
		return nil, err
	}
	return &PublicKey{key: e.ScalarBaseMult(sc)}, nil
}

func (p *PublicKey) Decode(in [32]byte) error {
	p.key = r255.NewElement()
	return p.key.Decode(in[:])
}

// Compress returns the encoding of the point underlying the public key
func (p *PublicKey) Compress() [32]byte {
	b := p.key.Encode([]byte{})
	enc := [32]byte{}
	copy(enc[:], b)
	return enc
}

// Encode is a wrapper around compress
func (p *PublicKey) Encode() [32]byte {
	return p.Compress()
}
