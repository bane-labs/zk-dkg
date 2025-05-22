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
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
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
	fiBytes, fiInt, bigFi := transformKeyShare(fi)
	nonce, encryptedFi, r, bigR := encryptKeyShare(&privKey.PublicKey, fiBytes)
	// Verify circuit
	circuit := ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		PlainChunks:  make([]frontend.Variable, len(fiBytes)),
		CipherChunks: make([]frontend.Variable, len(encryptedFi)),
		PubInputHash: make([]frontend.Variable, 32),
	}
	assignment, _ := ComputeSingleKeyShareEncryptionAssignment(&privKey.PublicKey, r, bigR, fiBytes, fiInt, bigFi, encryptedFi, nonce)
	err = test.IsSolved(&circuit, assignment, ecc.BN254.ScalarField())
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
	fiBytes, fiInt, bigFi := transformKeyShare(fi)
	nonce, encryptedFi, r, bigR := encryptKeyShare(&privKey.PublicKey, fiBytes)
	// Compute proof
	circuit := ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		PlainChunks:  make([]frontend.Variable, len(fiBytes)),
		CipherChunks: make([]frontend.Variable, len(encryptedFi)),
		PubInputHash: make([]frontend.Variable, 32),
	}
	css, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(err)
	assignment, _ := ComputeSingleKeyShareEncryptionAssignment(&privKey.PublicKey, r, bigR, fiBytes, fiInt, bigFi, encryptedFi, nonce)
	_, vk, proof, witness, err := computingProof2(css, assignment)
	assert.NoError(err)
	publicWitness, err := witness.Public()
	assert.NoError(err)
	// Verify proof
	err = groth16.Verify(proof, vk, publicWitness.Vector().(fr_bn254.Vector))
	assert.NoError(err)
	// Export solidity contract
	helper.ExportContract(vk, "Verify.sol")
	// Output verify data
	//helper.GetContractInput(proof)
}

func computingProof2(css constraint.ConstraintSystem, assignment frontend.Circuit) (*groth16.ProvingKey, *groth16.VerifyingKey, *groth16.Proof, witness.Witness, error) {
	pk, vk, err := demoMPCSetUp(css, 3, 3, 16777216) //2^24
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// Setup
	err = groth16.Setup(css.(*cs.R1CS), pk, vk)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// Compute witness
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// Compute proof
	proof, err := groth16.Prove(css.(*cs.R1CS), pk, witness, backend.WithProverHashToFieldFunction(sha256.New()))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return pk, vk, proof, witness, err
}

// nContributionsPhase1 = 3
// nContributionsPhase2 = 3
// power                = 22 //element count range 2^0-2^27
func demoMPCSetUp(ccs constraint.ConstraintSystem, nContributionsPhase1 int, nContributionsPhase2 int, power int) (*groth16.ProvingKey, *groth16.VerifyingKey, error) {
	_, err := mpc.InitGroth16Phase1("Phase1_1", uint64(power))
	if err != nil {
		return nil, nil, err
	}
	// All members build and verify contributions for phase1
	for i := 1; i < nContributionsPhase1; i++ {
		prepath := "Phase1_" + strconv.Itoa(i)
		nextPath := "Phase1_" + strconv.Itoa(i+1)
		_, err = mpc.ContributeGroth16Phase1(prepath, nextPath)
		if err != nil {
			return nil, nil, err
		}
	}
	mpc.SealGroth16Phase1("Phase1_"+strconv.Itoa(nContributionsPhase1), "Phase1_final")

	evals, srs, _, err := mpc.InitGroth16Phase2(ccs, "Phase1_Phase1_final", "Phase2_1")
	if err != nil {
		return nil, nil, err
	}
	// All members build and verify contributions for phase2
	for i := 1; i < nContributionsPhase2; i++ {
		prepath := "Phase2_" + strconv.Itoa(i)
		nextPath := "Phase2_" + strconv.Itoa(i+1)
		_, err = mpc.ContributeGroth16Phase2(prepath, nextPath)
		if err != nil {
			return nil, nil, err
		}
	}
	phase2, err := mpc.ReadGroth16Phase2FromFile("Phase2_" + strconv.Itoa(nContributionsPhase1))
	if err != nil {
		return nil, nil, err
	}
	// Extract the proving and verifying keys
	p1, v1 := phase2.Seal(srs, evals, []byte("beacon Phase 2"))
	pk := p1.(*groth16.ProvingKey)
	vk := v1.(*groth16.VerifyingKey)
	return pk, vk, err
}
