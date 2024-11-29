package circuit

import (
	"crypto/sha256"
	"math/rand"
	"strconv"
	"testing"
	"time"

	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	"github.com/bane-labs/zk-dkg/helper"
	"github.com/bane-labs/zk-dkg/mpc"
	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

func TestECIESCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	// Generate a private key
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	privKey, err := ecies.GenerateKey(rand, crypto.S256(), nil)
	assert.NoError(err)
	// Generate an encrypt fragement key
	var fi fr_bls12381.Element
	fi.SetRandom()
	fiBytes, sfi, bfi, nonce, ctt, rs, rb := GenerateEncryptFragementKey(privKey.PublicKey, fi)
	// Compute proof
	_, circuit, assignment, err := ComputingAssignment(privKey.PublicKey, rs, rb, fiBytes, sfi, bfi, ctt, nonce)
	assert.NoError(err)
	err = test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestECIESWithMPC(t *testing.T) {
	assert := test.NewAssert(t)
	// Generate a private key
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	privKey, err := ecies.GenerateKey(rand, crypto.S256(), nil)
	assert.NoError(err)
	// Generate a encrypt fragement key
	var fi fr_bls12381.Element
	fi.SetRandom()
	fiBytes, sfi, bfi, nonce, ctt, rs, rb := GenerateEncryptFragementKey(privKey.PublicKey, fi)
	// Compute proof (two ways)
	// 1) From an existing MPC file
	/*	phase1Path := "Phase1_" + strconv.Itoa(3)
		phase2Path := "Phase2_" + strconv.Itoa(3)
		vk, proof, witness, err := GenerateProof(phase1Path, phase2Path, privKey.PublicKey, rs, rb, fiBytes, sfi, bfi, ctt, nonce)*/
	// 2) From a new MPC file
	css, _, assignment, err := ComputingAssignment(privKey.PublicKey, rs, rb, fiBytes, sfi, bfi, ctt, nonce)
	assert.NoError(err)
	_, vk, proof, witness, err := computingProof2(css, &assignment)
	assert.NoError(err)
	publicWitness, err := witness.Public()
	assert.NoError(err)
	// Verify proof
	err = groth16.Verify(proof, &vk, publicWitness.Vector().(fr_bn254.Vector))
	assert.NoError(err)
	// Export solidity contract
	helper.ExportContract(vk)
	// Output verify data
	helper.GetOutputData(proof)
}

func computingProof2(css constraint.ConstraintSystem, assignment frontend.Circuit) (groth16.ProvingKey, groth16.VerifyingKey, *groth16.Proof, witness.Witness, error) {
	pk, vk, err := demoMPCSetUp(css, 3, 3, 24)
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, nil, nil, err
	}
	// Setup
	err = groth16.Setup(css.(*cs.R1CS), &pk, &vk)
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, nil, nil, err
	}
	// Compute witness
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, nil, nil, err
	}
	// Compute proof
	proof, err := groth16.Prove(css.(*cs.R1CS), &pk, witness, backend.WithProverHashToFieldFunction(sha256.New()))
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, nil, nil, err
	}
	return pk, vk, proof, witness, err
}

// nContributionsPhase1 = 3
// nContributionsPhase2 = 3
// power                = 22 //element count range 2^0-2^27
func demoMPCSetUp(ccs constraint.ConstraintSystem, nContributionsPhase1 int, nContributionsPhase2 int, power int) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	_, err := mpc.InitPhase1("Phase1_1", power)
	if err != nil {
		return pk, vk, err
	}
	// All members build and verify contributions for phase1
	for i := 1; i < nContributionsPhase1; i++ {
		prepath := "Phase1_" + strconv.Itoa(i)
		nextPath := "Phase1_" + strconv.Itoa(i+1)
		_, _, err = mpc.ContributePhase1(prepath, nextPath)
		if err != nil {
			return pk, vk, err
		}
	}
	evals, srs1, _, err := mpc.InitPhase2(ccs, "Phase1_"+strconv.Itoa(nContributionsPhase1), "Phase2_1")
	if err != nil {
		return pk, vk, err
	}
	// All members build and verify contributions for phase2
	for i := 1; i < nContributionsPhase2; i++ {
		prepath := "Phase2_" + strconv.Itoa(i)
		nextPath := "Phase2_" + strconv.Itoa(i+1)
		_, _, err = mpc.ContributePhase2(prepath, nextPath)
		if err != nil {
			return pk, vk, err
		}
	}
	srs2, err := mpc.ReadPhase2FromFile("Phase2_" + strconv.Itoa(nContributionsPhase1))
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
	}
	// Extract the proving and verifying keys
	pk, vk = mpcsetup.ExtractKeys(&srs1, &srs2, &evals, ccs.GetNbConstraints())
	return pk, vk, err
}
