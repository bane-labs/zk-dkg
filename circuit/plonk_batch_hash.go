package circuit

import (
	"fmt"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"

	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

type InnerHashCircuit struct {
	PubInputHash []frontend.Variable `gnark:",public"`
	X            frontend.Variable   `gnark:",secret"`
	Y            frontend.Variable   `gnark:",secret"`
}

func (c *InnerHashCircuit) Define(api frontend.API) error {
	X := c.X
	Y := c.Y
	//verify hash=hash(x,y)
	pubInputs := make([]uints.U8, 2)
	pubInputs[0] = uints.U8{Val: X}
	pubInputs[1] = uints.U8{Val: Y}
	hasher, err := sha2.New(api)
	if err != nil {
		return err
	}
	hasher.Write(pubInputs)
	result := hasher.Sum()

	for i := 0; i < len(result); i++ {
		api.AssertIsEqual(result[i].Val, c.PubInputHash[i])
	}
	//verify x==y
	api.AssertIsEqual(X, Y)
	return nil
}

type OuterHashCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        []stdgroth16.Proof[G1El, G2El]
	VerifyingKey []stdgroth16.VerifyingKey[G1El, G2El, GtEl] `gnark:"-"`
	InnerWitness []stdgroth16.Witness[FR]
	PublicInputs []frontend.Variable `gnark:",public"`
}

func (c *OuterHashCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	hasher, err := sha2.New(api)
	if err != nil {
		return err
	}

	for i := 0; i < len(c.Proof); i++ {
		verifier, err := stdgroth16.NewVerifier[FR, G1El, G2El, GtEl](api)
		if err != nil {
			return fmt.Errorf("new verifier: %w", err)
		}
		err = verifier.AssertProof(c.VerifyingKey[i], c.Proof[i], c.InnerWitness[i])
		if err != nil {
			return fmt.Errorf("inner circuit verify fault: %w", err)
		}
		nbBits := 8 * ((fr_bn254.Modulus().BitLen() + 7) / 8)
		for _, input := range c.InnerWitness[i].Public {
			// Write the limbs of each public input to the hash function
			innerhash := variableToU8s(input.Limbs, nbBits)
			hasher.Write(innerhash)
		}
	}
	result := hasher.Sum()
	//api.AssertIsEqual(result, c.PublicInputs)
	for i := 0; i < len(result); i++ {
		api.AssertIsEqual(result[i].Val, c.PublicInputs[i])
	}
	return nil
}
