package schnorrkel

import (
	"github.com/noot/merlin"
	r255 "github.com/noot/ristretto255"
)

type Signature struct {
	R	*r255.Element
	S 	*r255.Scalar
}

// Sign 
// See the following for the transcript message
// https://github.com/w3f/schnorrkel/blob/db61369a6e77f8074eb3247f9040ccde55697f20/src/sign.rs#L158
func (sk *SecretKey) Sign(t *merlin.Transcript) (*Signature, error) {
	t.AppendMessage([]byte("proto-name"), []byte("Schnorr-sig"))

	pub, err := sk.Public()
	if err != nil {
		return nil, err
	}
	pubc := pub.Compress()
	t.AppendMessage([]byte("sign:pk"), pubc[:])

	// note: merlin library doesn't have build_rng yet. this is not complete
	// need to also add nonce: see https://github.com/w3f/schnorrkel/blob/798ab3e0813aa478b520c5cf6dc6e02fd4e07f0a/src/context.rs#L153
	//r := t.ExtractBytes([]byte("signing"), 32)

	r, err := NewRandomScalar()
	if err != nil {
		return nil, err
	}
	R := r255.NewElement().ScalarBaseMult(r)
	t.AppendMessage([]byte("sign:R"), R.Encode([]byte{}))
	kb := t.ExtractBytes([]byte("sign:c"), 64)
	k := r255.NewScalar()
	k.FromUniformBytes(kb)

	ss, err := ScalarFromBytes(sk.key)
	if err != nil {
		return nil, err
	}

	s := ss.Multiply(ss, k).Add(ss, r)

	return &Signature{R: R, S: s}, nil
}