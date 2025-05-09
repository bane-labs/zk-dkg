package circuit

import (
	"math/big"
	"os"
	"strconv"
	"testing"

	"github.com/bane-labs/zk-dkg/helper"
	"github.com/bane-labs/zk-dkg/mpc"
	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/test/unsafekzg"

	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

func TestPlonkRecursion(t *testing.T) {
	innerCcs, innerVK, innerWitness, innerProof := computeInnerProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField())
	// initialize the witness elements
	circuitVk, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVK)
	if err != nil {
		panic(err)
	}
	circuitWitness, err := stdgroth16.ValueOfWitness[sw_bn254.ScalarField](innerWitness)
	if err != nil {
		panic(err)
	}
	circuitProof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerProof)
	if err != nil {
		panic(err)
	}

	outerAssignment := &OuterCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}

	outerCircuit := &OuterCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness: stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs),
		VerifyingKey: stdgroth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerCcs),
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, outerCircuit)
	if err != nil {
		panic(err)
	}
	scs := ccs.(*cs.SparseR1CS)
	srs, srsLagrange, err := unsafekzg.NewSRS(scs)
	if err != nil {
		panic(err)
	}

	witness, err := frontend.NewWitness(outerAssignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	witnessPub, err := witness.Public()
	if err != nil {
		panic(err)
	}
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		panic(err)
	}
	proof, err := plonk.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}
	err = plonk.Verify(proof, vk, witnessPub)
	if err != nil {
		panic(err)
	}
}

func TestPlonkRecursionBatch(t *testing.T) {
	var batch = 1
	innerCcs, innerVK, innerWitness, innerProof := computeInnerProofBatch(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), batch)
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

	outerAssignment := &OuterBatchCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		//VerifyingKey: circuitVk,
	}

	outerCircuit := &OuterBatchCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness: make([]stdgroth16.Witness[sw_bn254.ScalarField], batch),
		VerifyingKey: circuitVk,
		//VerifyingKey: make([]stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl], batch),
		Proof: make([]stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine], batch),
	}

	for i := 0; i < batch; i++ {
		outerCircuit.InnerWitness[i] = stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs[i])
		//outerCircuit.VerifyingKey[i] = stdgroth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerCcs[i])
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, outerCircuit)
	if err != nil {
		panic(err)
	}
	scs := ccs.(*cs.SparseR1CS)
	srs, srsLagrange, err := unsafekzg.NewSRS(scs)
	if err != nil {
		panic(err)
	}

	witness, err := frontend.NewWitness(outerAssignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	witnessPub, err := witness.Public()
	if err != nil {
		panic(err)
	}
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		panic(err)
	}
	proof, err := plonk.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}
	err = plonk.Verify(proof, vk, witnessPub)
	if err != nil {
		panic(err)
	}
	/*	p := proof.(*plonk_bn254.Proof)
		serializedProof := p.MarshalSolidity()*/
	f, err := os.Create("contract_plonk.sol")
	if err != nil {
		panic(err)
	}
	err = vk.ExportSolidity(f)
	if err != nil {
		panic(err)
	}
}

func computeInnerProof(field, outer *big.Int) (constraint.ConstraintSystem, *groth16.VerifyingKey, witness.Witness, *groth16.Proof) {
	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &InnerCircuit{})
	if err != nil {
		panic(err)
	}
	innerPK, innerVK, err := mockMPCSetUp(innerCcs, 2, 2, 2)
	if err != nil {
		panic(err)
	}
	r1cs := innerCcs.(*cs.R1CS)
	err = groth16.Setup(innerCcs.(*cs.R1CS), innerPK, innerVK)
	if err != nil {
		panic(err)
	}

	// inner proof
	innerAssignment := &InnerCircuit{
		X: 5,
		Y: 5,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	if err != nil {
		panic(err)
	}
	innerProof, err := groth16.Prove(r1cs, innerPK, innerWitness, stdgroth16.GetNativeProverOptions(outer, field))
	if err != nil {
		panic(err)
	}
	innerPubWitness, err := innerWitness.Public()
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(innerProof, innerVK, innerPubWitness.Vector().(fr_bn254.Vector), stdgroth16.GetNativeVerifierOptions(outer, field))
	if err != nil {
		panic(err)
	}
	return innerCcs, innerVK, innerPubWitness, innerProof
}

func computeInnerProofBatch(field, outer *big.Int, batch int) ([]constraint.ConstraintSystem, []*groth16.VerifyingKey, []witness.Witness, []*groth16.Proof) {

	innerCcss := make([]constraint.ConstraintSystem, batch)
	innerVKs := make([]*groth16.VerifyingKey, batch)
	innerPubWitnesss := make([]witness.Witness, batch)
	innerProofs := make([]*groth16.Proof, batch)

	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &InnerCircuit{})
	if err != nil {
		panic(err)
	}
	innerPK, innerVK, err := mockMPCSetUp(innerCcs, 2, 2, 2)
	if err != nil {
		panic(err)
	}
	r1cs := innerCcs.(*cs.R1CS)
	err = groth16.Setup(innerCcs.(*cs.R1CS), innerPK, innerVK)
	if err != nil {
		panic(err)
	}

	// inner proof
	innerAssignment := &InnerCircuit{
		X: 5,
		Y: 5,
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

func mockMPCSetUp(ccs constraint.ConstraintSystem, nContributionsPhase1 int, nContributionsPhase2 int, power int) (*groth16.ProvingKey, *groth16.VerifyingKey, error) {
	_, err := mpc.InitPhase1("Phase1_1", uint64(power))
	if err != nil {
		return nil, nil, err
	}
	// All members build and verify contributions for phase1
	for i := 1; i < nContributionsPhase1; i++ {
		prepath := "Phase1_" + strconv.Itoa(i)
		nextPath := "Phase1_" + strconv.Itoa(i+1)
		_, err = mpc.ContributePhase1(prepath, nextPath)
		if err != nil {
			return nil, nil, err
		}
	}
	mpc.Seal("Phase1_"+strconv.Itoa(nContributionsPhase1), "Phase1_final")

	evals, srs, _, err := mpc.InitPhase2(ccs, "Phase1_final", "Phase2_1")
	if err != nil {
		return nil, nil, err
	}
	// All members build and verify contributions for phase2
	for i := 1; i < nContributionsPhase2; i++ {
		prepath := "Phase2_" + strconv.Itoa(i)
		nextPath := "Phase2_" + strconv.Itoa(i+1)
		_, err = mpc.ContributePhase2(prepath, nextPath)
		if err != nil {
			return nil, nil, err
		}
	}
	phase2, err := mpc.ReadPhase2FromFile("Phase2_" + strconv.Itoa(nContributionsPhase1))
	if err != nil {
		return nil, nil, err
	}
	// Extract the proving and verifying keys
	p1, v1 := phase2.Seal(&srs, &evals, []byte("beacon Phase 2"))
	pk := p1.(*groth16.ProvingKey)
	vk := v1.(*groth16.VerifyingKey)
	helper.ExportProvingKey(pk, "test_pk")
	helper.ExportVerifyingKey(vk, "test_vk")
	helper.ExportCSS(ccs, "test_ccs")
	return pk, vk, err
}
