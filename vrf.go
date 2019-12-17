package schnorrkel

import (
	"github.com/gtank/merlin"
	r255 "github.com/gtank/ristretto255"
)

type VrfInOut struct {
	input *r255.Element
	output *r255.Element
}

type VrfProof struct {
	c *r255.Scalar
	s *r255.Scalar
}

func (sk *SecretKey) VrfSign(t *merlin.Transcript) (*VrfInOut, *VrfProof, error) {
	p, err := sk.VrfCreateHash(t)
	if err != nil {
		return nil, nil, err
	}

	t0 := merlin.NewTranscript("VRF")
	proof, err := sk.ProduceProof(t0, p)
	if err != nil {
		return nil, nil, err
	}
	return p, proof, nil
}

func (sk *SecretKey) ProduceProof(t *merlin.Transcript, p *VrfInOut) (*VrfProof, error) {
	t.AppendMessage([]byte("proto-name"), []byte("DLEQProof"))
	t.AppendMessage([]byte("vrf:h"), p.input.Encode([]byte{}))

	// create random element R = g^r
	r, err := NewRandomScalar()
	if err != nil {
		return nil, err
	}
	R := r255.NewElement()
	R.ScalarBaseMult(r)
	t.AppendMessage([]byte("vrf:R=g^r"), R.Encode([]byte{}))

	// create hr := HashToElement(input)
	//hr := r255.NewElement().ScalarMult(r, p.input).Encode([]byte{})

	return nil, nil
}

// VrfCreateHash creates a VRF input/output pair on the given transcript.
func (sk *SecretKey) VrfCreateHash(t *merlin.Transcript) (*VrfInOut, error) {
	pub, err := sk.Public()
	if err != nil {
		return nil, err
	}
	input := pub.VrfHash(t)

	output := r255.NewElement()
	sc := r255.NewScalar()
	err = sc.Decode(sk.key[:])
	if err != nil {
		return nil, err
	}
	output.ScalarMult(sc, input)

	return &VrfInOut{
		input: input,
		output: output,
	}, nil
}

// VrfHash creates a VRF input point by hashing the transcript to a point.
func (pk *PublicKey) VrfHash(t *merlin.Transcript) *r255.Element {
	mt := TranscriptWithMalleabilityAddressed(t, pk)
	hash := mt.ExtractBytes([]byte("VRFHash"), 64)
	point := r255.NewElement()
	point.FromUniformBytes(hash)
	return point
}

// TranscriptWithMalleabilityAddressed returns the input transcript with the public key commited to it,
// addressing VRF output malleability.
func TranscriptWithMalleabilityAddressed(t *merlin.Transcript, pk *PublicKey) *merlin.Transcript {
	enc := pk.Encode()
	t.AppendMessage([]byte("vrf-nm-pk"), enc[:])
	return t
}