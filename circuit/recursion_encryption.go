package circuit

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	stdplonk "github.com/consensys/gnark/std/recursion/plonk"
)

// RecursionEncryptionWrapper is the circuit for proving the verification of a batch of ECIES encryptions.
type RecursionEncryptionWrapper[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        stdplonk.Proof[FR, G1El, G2El]          `gnark:",secret"`
	VerifyingKey []stdplonk.VerifyingKey[FR, G1El, G2El] `gnark:"-"`
	VerifyingID  []frontend.Variable                     `gnark:"-"`
	InnerWitness stdplonk.Witness[FR]                    `gnark:",secret"`
	SumHash      []frontend.Variable                     `gnark:",public"`
	Batch        frontend.Variable                       `gnark:",public"`
}

// Define declares the circuit's constraints
// Need check batch==VerifyingID[index] outside
func (c *RecursionEncryptionWrapper[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	field, err := emulated.NewField[FR](api)
	if err != nil {
		return err
	}
	var i int
	for i = 0; i < len(c.VerifyingID); i++ {
		if c.Batch == c.VerifyingID[i] {
			verifier, err := stdplonk.NewVerifier[FR, G1El, G2El, GtEl](api)
			if err != nil {
				return fmt.Errorf("new verifier: %w", err)
			}
			err = verifier.AssertProof(c.VerifyingKey[i], c.Proof, c.InnerWitness)
			if err != nil {
				return fmt.Errorf("inner circuit verify fault: %w", err)
			}
			uapi, err := uints.New[uints.U64](api)
			if err != nil {
				return err
			}
			innerhash := make([]uints.U8, 32)
			for j, input := range c.InnerWitness.Public {
				inputbits := field.ToBits(&input)
				innerhash[j] = uapi.ByteValueOf(bits.FromBinary(api, inputbits, bits.WithUnconstrainedInputs()))
			}
			for i := 0; i < len(innerhash); i++ {
				api.AssertIsEqual(innerhash[i].Val, c.SumHash[i])
			}
		}
	}
	return nil
}
