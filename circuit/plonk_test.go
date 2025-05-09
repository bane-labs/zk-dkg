package circuit

import (
	"fmt"
	"github.com/bane-labs/zk-dkg/helper"
	"github.com/bane-labs/zk-dkg/mpc"
	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
	"math/big"
	"math/rand"
	"os"
	"strconv"
	"testing"
	"time"

	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

type Circuit struct {
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`
}

// y == x**e
func (circuit *Circuit) Define(api frontend.API) error {
	X := circuit.X
	Y := circuit.Y

	api.AssertIsEqual(X, Y)
	return nil
}

func TestPlonk(t *testing.T) {
	var circuit Circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	scs := ccs.(*cs.SparseR1CS)
	srs, srsLagrange, err := unsafekzg.NewSRS(scs)
	if err != nil {
		panic(err)
	}

	var w Circuit
	w.X = 4
	w.Y = 4

	witness, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	witnessPub, err := witness.Public()
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

func TestPlonkByMPC(t *testing.T) {
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	var circuit Circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	sizeSystem, lagrange := plonk.SRSSize(ccs)
	bAlpha := new(big.Int).SetInt64(rand.Int63())
	srs, err := kzg_bn254.NewSRS(uint64(sizeSystem), bAlpha)
	if err != nil {
		panic(err)
	}
	srsLagrange, err := kzg_bn254.NewSRS(uint64(sizeSystem), bAlpha)
	srsLagrange.Vk = srs.Vk
	srsLagrange.Pk.G1, _ = kzg_bn254.ToLagrangeG1(srs.Pk.G1[:lagrange])
	if err != nil {
		panic(err)
	}

	var w Circuit
	w.X = 4
	w.Y = 4

	witness, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	witnessPub, err := witness.Public()
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

type InnerCircuitNative struct {
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`
}

func (c *InnerCircuitNative) Define(api frontend.API) error {
	X := c.X
	Y := c.Y

	api.AssertIsEqual(X, Y)
	return nil
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

func computeInnerProof(field, outer *big.Int) (constraint.ConstraintSystem, *groth16.VerifyingKey, witness.Witness, *groth16.Proof) {
	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &InnerCircuitNative{})
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
	innerAssignment := &InnerCircuitNative{
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

	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &InnerCircuitNative{})
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
	innerAssignment := &InnerCircuitNative{
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

type InnerCircuitByHash struct {
	PubInputHash []frontend.Variable `gnark:",public"`
	X            frontend.Variable   `gnark:",secret"`
	Y            frontend.Variable   `gnark:",secret"`
}

func (c *InnerCircuitByHash) Define(api frontend.API) error {
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
	err = groth16.Setup(innerCcs.(*cs.R1CS), innerPK, innerVK)
	if err != nil {
		panic(err)
	}

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

	innerAssignment := &InnerCircuitByHash{
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

type OuterCircuitByHash[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        []stdgroth16.Proof[G1El, G2El]
	VerifyingKey []stdgroth16.VerifyingKey[G1El, G2El, GtEl] `gnark:"-"`
	InnerWitness []stdgroth16.Witness[FR]
	PublicInputs []frontend.Variable `gnark:",public"`
}

func (c *OuterCircuitByHash[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
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

func TestPlonkRecursionHash(t *testing.T) {
	//mock inner circuit
	/*	mockinnerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &InnerCircuitByHash{PubInputHash: make([]frontend.Variable, 32)})
		if err != nil {
			panic(err)
		}
		_, _, err = mockMPCSetUp(mockinnerCcs, 2, 2, 262144)
		if err != nil {
			panic(err)
		}*/
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

	outerAssignment := &OuterCircuitByHash[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		//VerifyingKey: circuitVk,
		PublicInputs: rawSumHash,
	}

	outerCircuit := &OuterCircuitByHash[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
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

	err := test.IsSolved(outerCircuit, outerAssignment, ecc.BW6_761.ScalarField())
	if err != nil {
		panic(err)
	}

	/*	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, outerCircuit)
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
		}*/
	/*	p := proof.(*plonk_bn254.Proof)
		serializedProof := p.MarshalSolidity()*/
	/*	f, err := os.Create("contract_plonk.sol")
		if err != nil {
			panic(err)
		}
		err = vk.ExportSolidity(f)
		if err != nil {
			panic(err)
		}*/
}
