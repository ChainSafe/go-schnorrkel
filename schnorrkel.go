package schnorrkel

import (
	"crypto/rand"
	"encoding/binary"

	r255 "github.com/gtank/ristretto255"
)

type SecretKey [32]byte
type PubKey *r255.Element

// order of the ristretto255 group
var order = [4]uint64{0x5812631a5cf5d3ed, 0x14def9dea2f79cd6, 0, 0x1000000000000000}

// scMinimal returns true if the given scalar is less than the order of the
// curve.
func scMinimal(sc []byte) bool {
	for i := 3; ; i-- {
		v := binary.LittleEndian.Uint64(sc[i*8:])
		if v > order[i] {
			return false
		} else if v < order[i] {
			break
		} else if i == 0 {
			return false
		}
	}

	return true
}

func GenerateKeypair() (priv SecretKey, pub PubKey, err error) {
	e := r255.NewElement()

	// generate random scalar for private key
	for {
		priv = [32]byte{}
		_, err = rand.Read(priv[:])
		if err != nil {
			return [32]byte{}, nil, err
		}
		if scMinimal(priv[:]) {
			break
		}
	}

	// decodes priv bytes as little-endian
	scpriv := r255.NewScalar()
	err = scpriv.Decode(priv[:])
	if err != nil {
		return [32]byte{}, nil, err
	}

	// pub = g^s
	pub = e.ScalarBaseMult(scpriv)
	return priv, pub, nil
}
