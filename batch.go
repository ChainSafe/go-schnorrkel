package schnorrkel

import (
	"errors"

	"github.com/gtank/merlin"
	r255 "github.com/gtank/ristretto255"
)

// VerifyBatch batch verifies the given signatures
func VerifyBatch(transcripts []*merlin.Transcript, signatures []*Signature, pubkeys []*PublicKey) (bool, error) {
	if len(transcripts) != len(signatures) || len(signatures) != len(pubkeys) || len(pubkeys) != len(transcripts) {
		return false, errors.New("the number of transcripts, signatures, and public keys must be equal")
	}

	zero := r255.NewElement().Zero()

	// compute H(R_i || P_i || m_i)
	hs := make([]*r255.Scalar, len(transcripts))
	s := make([]r255.Scalar, len(transcripts))
	for i, t := range transcripts {
		t.AppendMessage([]byte("proto-name"), []byte("Schnorr-sig"))
		pubc := pubkeys[i].Compress()
		t.AppendMessage([]byte("sign:pk"), pubc[:])
		t.AppendMessage([]byte("sign:R"), signatures[i].R.Encode([]byte{}))

		h := t.ExtractBytes([]byte("sign:c"), 64)
		s[i] = *r255.NewScalar()
		hs[i] = &s[i]
		hs[i].FromUniformBytes(h)
	}

	// compute ∑ P_i H(R_i || P_i || m_i)
	ps := make([]*r255.Element, len(pubkeys))
	for i, p := range pubkeys {
		ps[i] = p.key
	}

	phs := r255.NewElement().MultiScalarMult(hs, ps)

	// compute ∑ s_0 ... s_n and  ∑ R_0 ... R_n
	ss := r255.NewScalar()
	rs := r255.NewElement()
	for _, s := range signatures {
		ss = r255.NewScalar().Add(ss, s.S)
		rs = r255.NewElement().Add(rs, s.R)
	}

	// ∑ P_i H(R_i || P_i || m_i) + ∑ R_i
	z := r255.NewElement().Add(phs, rs)

	// B ∑ s_i
	sb := r255.NewElement().ScalarBaseMult(ss)

	// check  -B ∑ s_i + ∑ P_i H(R_i || P_i || m_i) + ∑ R_i = 0
	sb_neg := r255.NewElement().Negate(sb)
	res := r255.NewElement().Add(sb_neg, z)

	return res.Equal(zero) == 1, nil
}

type BatchVerifier struct {
	hs      []*r255.Scalar // transcript scalar
	ss      *r255.Scalar   // sum of signature.S: ∑ s_0 ... s_n
	rs      *r255.Element  // sum of signature.R: ∑ R_0 ... R_n
	pubkeys []*r255.Element
}

func NewBatchVerifier() *BatchVerifier {
	return &BatchVerifier{
		hs:      []*r255.Scalar{},
		ss:      r255.NewScalar(),
		rs:      r255.NewElement(),
		pubkeys: []*r255.Element{},
	}
}

func (v *BatchVerifier) Add(t *merlin.Transcript, sig *Signature, pubkey *PublicKey) error {
	if t == nil {
		return errors.New("provided transcript is nil")
	}

	if sig == nil {
		return errors.New("provided signature is nil")
	}

	if pubkey == nil {
		return errors.New("provided public key is nil")
	}

	t.AppendMessage([]byte("proto-name"), []byte("Schnorr-sig"))
	pubc := pubkey.Compress()
	t.AppendMessage([]byte("sign:pk"), pubc[:])
	t.AppendMessage([]byte("sign:R"), sig.R.Encode([]byte{}))

	h := t.ExtractBytes([]byte("sign:c"), 64)
	s := r255.NewScalar()
	s.FromUniformBytes(h)
	v.hs = append(v.hs, s)

	v.ss.Add(v.ss, sig.S)
	v.rs.Add(v.rs, sig.R)

	v.pubkeys = append(v.pubkeys, pubkey.key)
	return nil
}

func (v *BatchVerifier) Verify() bool {
	zero := r255.NewElement().Zero()

	// compute ∑ P_i H(R_i || P_i || m_i)
	phs := r255.NewElement().MultiScalarMult(v.hs, v.pubkeys)

	// ∑ P_i H(R_i || P_i || m_i) + ∑ R_i
	z := r255.NewElement().Add(phs, v.rs)

	// B ∑ s_i
	sb := r255.NewElement().ScalarBaseMult(v.ss)

	// check  -B ∑ s_i + ∑ P_i H(R_i || P_i || m_i) + ∑ R_i = 0
	sb_neg := r255.NewElement().Negate(sb)
	res := r255.NewElement().Add(sb_neg, z)

	return res.Equal(zero) == 1
}
