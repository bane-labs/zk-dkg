package circuit

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

type RecursionEncryptionWrapper[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        []stdgroth16.Proof[G1El, G2El]              `gnark:",secret"`
	VerifyingKey []stdgroth16.VerifyingKey[G1El, G2El, GtEl] `gnark:"-"`
	InnerWitness []stdgroth16.Witness[FR]                    `gnark:",secret"`
	CommentsHash []frontend.Variable                         `gnark:",public"`
}

func (c *RecursionEncryptionWrapper[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	hasher, err := sha2.New(api)
	if err != nil {
		return err
	}
	field, err := emulated.NewField[FR](api)
	if err != nil {
		return err
	}
	allHash := make([]uints.U8, 0)
	for i := 0; i < len(c.Proof); i++ {
		verifier, err := stdgroth16.NewVerifier[FR, G1El, G2El, GtEl](api)
		if err != nil {
			return fmt.Errorf("new verifier: %w", err)
		}
		err = verifier.AssertProof(c.VerifyingKey[i], c.Proof[i], c.InnerWitness[i])
		if err != nil {
			return fmt.Errorf("inner circuit verify fault: %w", err)
		}
		uapi, err := uints.New[uints.U64](api)
		if err != nil {
			return err
		}
		innerhash := make([]uints.U8, 32)
		for j, input := range c.InnerWitness[i].Public {
			inputbits := field.ToBits(&input)
			innerhash[j] = uapi.ByteValueOf(bits.FromBinary(api, inputbits, bits.WithUnconstrainedInputs()))
		}
		allHash = append(allHash, innerhash...)
	}
	hasher.Write(allHash)
	result := hasher.Sum()
	for i := 0; i < len(result); i++ {
		api.AssertIsEqual(result[i].Val, c.CommentsHash[i])
	}
	return nil
}
