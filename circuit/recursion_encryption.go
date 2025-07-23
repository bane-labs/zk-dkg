package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	stdplonk "github.com/consensys/gnark/std/recursion/plonk"
)

// RecursionEncryptionWrapper is the circuit for proving the verification of a batch of ECIES encryptions.

type RecursionEncryptionWrapper[Fr emulated.FieldParams, G1 algebra.G1ElementT, G2 algebra.G2ElementT, GT algebra.GtElementT] struct {
	Proof                stdplonk.Proof[Fr, G1, G2]             `gnark:",secret"`
	BaseVerifyingKey     stdplonk.BaseVerifyingKey[Fr, G1, G2]  `gnark:"-"`              // all vks should use the same srsc, then the baseVerifyKey is same
	CircuitVerifyingKeys []stdplonk.CircuitVerifyingKey[Fr, G1] `gnark:"-"`              // CircuitVerifyKeys is related to the srsl and ccs
	InnerWitness         [32]emulated.Element[Fr]               `gnark:",publicWitness"` // Public inputs in inner circuit
	VerifyingKeyIndex    frontend.Variable                      `gnark:",public"`        // "Index" for choose which vk should be used in current proof generation
	SumHash              [32]frontend.Variable                  `gnark:",public"`        // hash of public inputs
}

// Define declares the circuit's constraints
func (c *RecursionEncryptionWrapper[Fr, G1, G2, GT]) Define(api frontend.API) error {
	field, err := emulated.NewField[Fr](api)
	if err != nil {
		return err
	}
	verifier, err := stdplonk.NewVerifier[Fr, G1, G2, GT](api)
	if err != nil {
		return err
	}
	vk, err := verifier.SwitchVerificationKey(c.BaseVerifyingKey, c.VerifyingKeyIndex, c.CircuitVerifyingKeys)
	if err != nil {
		return err
	}
	err = verifier.AssertProof(vk, c.Proof, stdplonk.Witness[Fr]{Public: c.InnerWitness[:]}, stdplonk.WithCompleteArithmetic())
	if err != nil {
		return nil
	}

	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return err
	}
	innerHash := [32]uints.U8{}
	for j, witness := range c.InnerWitness {
		inputbits := field.ToBits(&witness)
		innerHash[j] = uapi.ByteValueOf(bits.FromBinary(api, inputbits, bits.WithUnconstrainedInputs()))
	}
	for i := 0; i < len(innerHash); i++ {
		api.AssertIsEqual(innerHash[i].Val, c.SumHash[i])
	}

	return nil
}
