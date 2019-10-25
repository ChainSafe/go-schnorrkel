package schnorrkel

import (
	"github.com/noot/merlin"
	r255 "github.com/noot/ristretto255"
)

// Signature holds a schnorrkel signature
type Signature struct {
	R *r255.Element
	S *r255.Scalar
}

// Sign uses the schnorr signature algorithm to sign a message
// See the following for the transcript message
// https://github.com/w3f/schnorrkel/blob/db61369a6e77f8074eb3247f9040ccde55697f20/src/sign.rs#L158
// Schnorr w/ transcript, secret key x:
// 1. choose random r from group
// 2. R = gr
// 3. k = transcript.extract_bytes()
// 4. s = kx + r
// signature: (R, s)
// public key used for verification: y = g^x
func (sk *SecretKey) Sign(t *merlin.Transcript) (*Signature, error) {
	t.AppendMessage([]byte("proto-name"), []byte("Schnorr-sig"))

	pub, err := sk.Public()
	if err != nil {
		return nil, err
	}
	pubc := pub.Compress()

	t.AppendMessage([]byte("sign:pk"), pubc[:])

	// note: TODO: merlin library doesn't have build_rng yet. this is cannot yet be completed
	// need to also add nonce: see https://github.com/w3f/schnorrkel/blob/798ab3e0813aa478b520c5cf6dc6e02fd4e07f0a/src/context.rs#L153
	// r := t.ExtractBytes([]byte("signing"), 32)

	// choose random r
	r, err := NewRandomScalar()
	if err != nil {
		return nil, err
	}
	R := r255.NewElement().ScalarBaseMult(r)
	t.AppendMessage([]byte("sign:R"), R.Encode([]byte{}))

	// form k
	kb := t.ExtractBytes([]byte("sign:c"), 64)
	k := r255.NewScalar()
	k.FromUniformBytes(kb)

	// form scalar from secret key x
	x, err := ScalarFromBytes(sk.key)
	if err != nil {
		return nil, err
	}

	// s = kx + r
	s := x.Multiply(x, k).Add(x, r)

	return &Signature{R: R, S: s}, nil
}

// Verify verifies a schnorr signature with format: (R, s) where y is the public key
// 1. k = transcript.extract_bytes()
// 2. R' = -ky + gs
// 3. return R' == R
func (p *PublicKey) Verify(s *Signature, t *merlin.Transcript) bool {
	t.AppendMessage([]byte("proto-name"), []byte("Schnorr-sig"))
	pubc := p.Compress()
	t.AppendMessage([]byte("sign:pk"), pubc[:])
	t.AppendMessage([]byte("sign:R"), s.R.Encode([]byte{}))

	kb := t.ExtractBytes([]byte("sign:c"), 64)
	k := r255.NewScalar()
	k.FromUniformBytes(kb)

	Rp := r255.NewElement()
	Rp = Rp.ScalarBaseMult(s.S)
	ky := (p.key).ScalarMult(k, p.key)
	Rp = Rp.Subtract(Rp, ky)

	return Rp.Equal(s.R) == 1
}
