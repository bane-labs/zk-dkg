package circuit

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"

	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

type OuterCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        stdgroth16.Proof[G1El, G2El]
	VerifyingKey stdgroth16.VerifyingKey[G1El, G2El, GtEl]
	InnerWitness stdgroth16.Witness[FR]
}

func (c *OuterCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}

	return verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness)
}

type OuterBatchCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        []stdgroth16.Proof[G1El, G2El]
	VerifyingKey []stdgroth16.VerifyingKey[G1El, G2El, GtEl] `gnark:"-"`
	InnerWitness []stdgroth16.Witness[FR]
}

func (c *OuterBatchCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {

	for i := 0; i < len(c.Proof); i++ {
		verifier, err := stdgroth16.NewVerifier[FR, G1El, G2El, GtEl](api)
		if err != nil {
			return fmt.Errorf("new verifier: %w", err)
		}
		err = verifier.AssertProof(c.VerifyingKey[i], c.Proof[i], c.InnerWitness[i])
		if err != nil {
			return fmt.Errorf("inner circuit verify fault: %w", err)
		}
	}
	return nil
}
