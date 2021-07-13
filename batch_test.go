package schnorrkel

import (
	"fmt"
	"testing"

	"github.com/gtank/merlin"
	"github.com/stretchr/testify/require"
)

func ExampleVerifyBatch() {
	num := 16
	transcripts := make([]*merlin.Transcript, num)
	sigs := make([]*Signature, num)
	pubkeys := make([]*PublicKey, num)

	for i := 0; i < num; i++ {
		transcript := merlin.NewTranscript(fmt.Sprintf("hello_%d", i))
		priv, pub, err := GenerateKeypair()
		if err != nil {
			panic(err)
		}

		sigs[i], err = priv.Sign(transcript)
		if err != nil {
			panic(err)
		}

		transcripts[i] = merlin.NewTranscript(fmt.Sprintf("hello_%d", i))
		pubkeys[i] = pub
	}

	ok, err := VerifyBatch(transcripts, sigs, pubkeys)
	if err != nil {
		panic(err)
	}

	if !ok {
		fmt.Println("failed to batch verify signatures")
		return
	}

	fmt.Println("batch verified signatures")
	// Output: batch verified signatures
}

func ExampleBatchVerifier() {
	num := 16
	v := NewBatchVerifier()

	for i := 0; i < num; i++ {
		transcript := merlin.NewTranscript(fmt.Sprintf("hello_%d", i))
		priv, pub, err := GenerateKeypair()
		if err != nil {
			panic(err)
		}

		sig, err := priv.Sign(transcript)
		if err != nil {
			panic(err)
		}

		transcript = merlin.NewTranscript(fmt.Sprintf("hello_%d", i))
		err = v.Add(transcript, sig, pub)
		if err != nil {
			panic(err)
		}
	}

	ok := v.Verify()
	if !ok {
		fmt.Println("failed to batch verify signatures")
		return
	}

	fmt.Println("batch verified signatures")
	// Output: batch verified signatures
}

func TestBatchVerify(t *testing.T) {
	num := 16
	transcripts := make([]*merlin.Transcript, num)
	sigs := make([]*Signature, num)
	pubkeys := make([]*PublicKey, num)

	for i := 0; i < num; i++ {
		transcript := merlin.NewTranscript(fmt.Sprintf("hello_%d", i))
		priv, pub, err := GenerateKeypair()
		require.NoError(t, err)

		sigs[i], err = priv.Sign(transcript)
		require.NoError(t, err)

		transcripts[i] = merlin.NewTranscript(fmt.Sprintf("hello_%d", i))
		pubkeys[i] = pub
	}

	ok, err := VerifyBatch(transcripts, sigs, pubkeys)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestBatchVerify_Bad(t *testing.T) {
	num := 16
	transcripts := make([]*merlin.Transcript, num)
	sigs := make([]*Signature, num)
	pubkeys := make([]*PublicKey, num)

	for i := 0; i < num; i++ {
		transcript := merlin.NewTranscript(fmt.Sprintf("hello_%d", i))
		priv, pub, err := GenerateKeypair()
		require.NoError(t, err)

		sigs[i], err = priv.Sign(transcript)
		require.NoError(t, err)

		transcripts[i] = merlin.NewTranscript(fmt.Sprintf("hello_%d", i))
		pubkeys[i] = pub
	}

	transcripts[6] = merlin.NewTranscript(fmt.Sprintf("hello_%d", 999))
	ok, err := VerifyBatch(transcripts, sigs, pubkeys)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestBatchVerifier(t *testing.T) {
	num := 16
	v := NewBatchVerifier()

	for i := 0; i < num; i++ {
		transcript := merlin.NewTranscript(fmt.Sprintf("hello_%d", i))
		priv, pub, err := GenerateKeypair()
		require.NoError(t, err)

		sig, err := priv.Sign(transcript)
		require.NoError(t, err)

		transcript = merlin.NewTranscript(fmt.Sprintf("hello_%d", i))
		err = v.Add(transcript, sig, pub)
		require.NoError(t, err)
	}

	ok := v.Verify()
	require.True(t, ok)
}
