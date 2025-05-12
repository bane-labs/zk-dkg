package circuit

import (
	"math/big"
	"testing"

	"github.com/bane-labs/zk-dkg/helper"
	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/test"

	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

func TestPlonkRecursionHash(t *testing.T) {
	//mock inner circuit
	mockinnerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &InnerHashCircuit{PubInputHash: make([]frontend.Variable, 32)})
	if err != nil {
		panic(err)
	}
	_, _, err = mockMPCSetUp("", mockinnerCcs, 2, 2, 262144)
	if err != nil {
		panic(err)
	}
	//computer inner circuit
	var batch = 1
	innerCcs, innerVK, innerWitness, innerProof := getInnerProofBatch(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), batch)
	circuitVk := make([]stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl], batch)
	circuitWitness := make([]stdgroth16.Witness[sw_bn254.ScalarField], batch)
	circuitProof := make([]stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine], batch)
	for i := 0; i < batch; i++ {
		// initialize the witness elements
		var err error
		circuitVk[i], err = stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVK[i])
		if err != nil {
			panic(err)
		}
		circuitWitness[i], err = stdgroth16.ValueOfWitness[sw_bn254.ScalarField](innerWitness[i])
		if err != nil {
			panic(err)
		}
		circuitProof[i], err = stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerProof[i])
		if err != nil {
			panic(err)
		}
	}

	rawPubInputs := make([]byte, 2)
	rawPubInputs[0] = uint8(5)
	rawPubInputs[1] = uint8(5)
	temp := helper.GetHash(rawPubInputs)
	r := helper.GetHash(temp)
	rawSumHash := make([]frontend.Variable, len(r))
	for i := 0; i < len(r); i++ {
		rawSumHash[i] = r[i]
	}

	outerAssignment := &OuterHashCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		//VerifyingKey: circuitVk,
		PublicInputs: rawSumHash,
	}

	outerCircuit := &OuterHashCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness: make([]stdgroth16.Witness[sw_bn254.ScalarField], batch),
		//VerifyingKey: make([]stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl], batch),
		VerifyingKey: circuitVk,
		Proof:        make([]stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine], batch),
		PublicInputs: make([]frontend.Variable, 32),
	}

	for i := 0; i < batch; i++ {
		outerCircuit.InnerWitness[i] = stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs[i])
		outerCircuit.Proof[i] = stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs[i])
		//outerCircuit.VerifyingKey[i] = stdgroth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerCcs[i])
	}

	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
}

func getInnerProofBatch(field, outer *big.Int, batch int) ([]constraint.ConstraintSystem, []*groth16.VerifyingKey, []witness.Witness, []*groth16.Proof) {
	innerCcss := make([]constraint.ConstraintSystem, batch)
	innerVKs := make([]*groth16.VerifyingKey, batch)
	innerPubWitnesss := make([]witness.Witness, batch)
	innerProofs := make([]*groth16.Proof, batch)

	provingKeyPath := "test_pk"
	innerPK, err := helper.ReadProvingKey(provingKeyPath)
	if err != nil {
		panic(err)
	}
	verifyingKeyPath := "test_vk"
	innerVK, err := helper.ReadVerifyingKey(verifyingKeyPath)
	if err != nil {
		panic(err)
	}
	r1csPath := "test_ccs"
	innerCcs, err := helper.ReadCSS(r1csPath)
	if err != nil {
		panic(err)
	}
	r1cs := innerCcs.(*cs.R1CS)

	// inner proof
	var x = uint8(5)
	var y = uint8(5)
	rawPubInputs := make([]byte, 2)
	rawPubInputs[0] = x
	rawPubInputs[1] = y
	rawSumHash := make([]frontend.Variable, len(helper.GetHash(rawPubInputs)))
	for i := 0; i < len(helper.GetHash(rawPubInputs)); i++ {
		rawSumHash[i] = helper.GetHash(rawPubInputs)[i]
	}

	innerAssignment := &InnerHashCircuit{
		X:            x,
		Y:            y,
		PubInputHash: rawSumHash,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	if err != nil {
		panic(err)
	}
	innerPubWitness, err := innerWitness.Public()
	if err != nil {
		panic(err)
	}
	for i := 0; i < batch; i++ {
		innerProof, err := groth16.Prove(r1cs, innerPK, innerWitness, stdgroth16.GetNativeProverOptions(outer, field))
		if err != nil {
			panic(err)
		}
		err = groth16.Verify(innerProof, innerVK, innerPubWitness.Vector().(fr_bn254.Vector), stdgroth16.GetNativeVerifierOptions(outer, field))
		if err != nil {
			panic(err)
		}
		innerCcss[i] = innerCcs
		innerVKs[i] = innerVK
		innerPubWitnesss[i] = innerPubWitness
		innerProofs[i] = innerProof
	}

	return innerCcss, innerVKs, innerPubWitnesss, innerProofs
}
