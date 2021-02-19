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
	for i, t := range transcripts {
		t.AppendMessage([]byte("proto-name"), []byte("Schnorr-sig"))
		pubc := pubkeys[i].Compress()
		t.AppendMessage([]byte("sign:pk"), pubc[:])
		t.AppendMessage([]byte("sign:R"), signatures[i].R.Encode([]byte{}))

		h := t.ExtractBytes([]byte("sign:c"), 64)
		hs[i] = r255.NewScalar()
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
