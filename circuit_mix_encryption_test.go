package circom

import (
	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"math/rand"
	"strconv"
	"testing"
	"time"
)

func Test_MixEncryption_Circuit(t *testing.T) {
	//generate a private key
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	privKey, err := ecies.GenerateKey(rand, crypto.S256(), nil)
	//generate a encrypt fragement key
	fiBytes, sfi, bfi, nonce, ctt, rs, rb := GenerateEncryptFragementKey(privKey.PublicKey)
	//computing proof
	_, circuit, witness, err := computingAssignment(privKey.PublicKey, rs, rb, fiBytes, sfi, bfi, ctt, nonce)
	err = test.IsSolved(&circuit, witness, ecc.BN254.ScalarField())
	assert := test.NewAssert(t)
	assert.NoError(err)
}

func TestMixEncryptionByMPC(t *testing.T) {
	//generate a private key
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	privKey, err := ecies.GenerateKey(rand, crypto.S256(), nil)
	//generate a encrypt fragement key
	fiBytes, sfi, bfi, nonce, ctt, rs, rb := GenerateEncryptFragementKey(privKey.PublicKey)
	//computing proof 2 way
	//1)from existed mpc file
	phase1Path := "Phase1_" + strconv.Itoa(3)
	phase2Path := "Phase2_" + strconv.Itoa(3)
	vk, proof, witness, err := GenerateProof(phase1Path, phase2Path, privKey.PublicKey, rs, rb, fiBytes, sfi, bfi, ctt, nonce)
	//2)from a new mpc file
	/*	css, _, assignment, err := computingAssignment(privKey.PublicKey, rs, rb, fiBytes, sfi, bfi, ctt, nonce)
		if err != nil {
			panic(err)
		}
		_, vk, proof, witness, err := computingProof2(css, assignment)
		if err != nil {
			panic(err)
		}*/

	publicWitness, err := witness.Public()
	if err != nil {
		t.Fatalf(err.Error())
	}
	//verify proof
	err = groth16.Verify(proof, &vk, publicWitness.Vector().(fr_bn254.Vector))
	if err != nil {
		t.Fatalf(err.Error())
	}
	//export solidity contract
	ExportContract(vk)
	//output verify data
	GetVerifyInput(proof)
}

func computingProof2[T1, S1, T2, S2 emulated.FieldParams](css constraint.ConstraintSystem, assignment *MixEncryptionWrapper[T1, S1, T2, S2]) (pk groth16.ProvingKey, vk groth16.VerifyingKey, proof *groth16.Proof, witness witness.Witness, err error) {
	//init,2ways: way1 make a new mpc, way2 from a existed mpc
	pk, vk, _ = doMPCSetUp(css, 3, 3, 21)
	//pk, vk, _ = GetFromExistedMPCSetUp(css, phase1Path, phase2Path)
	// 1. One time setup
	err = groth16.Setup(css.(*cs.R1CS), &pk, &vk)
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, nil, nil, err
	}
	//compute witness
	witness, err = frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, nil, nil, err
	}
	// compute proof
	proof, err = groth16.Prove(css.(*cs.R1CS), &pk, witness)
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, nil, nil, err
	}
	return
}

// nContributionsPhase1 = 3
// nContributionsPhase2 = 3
// power                = 21 //element count range 2^0-2^27
func doMPCSetUp(ccs constraint.ConstraintSystem, nContributionsPhase1 int, nContributionsPhase2 int, power int) (pk groth16.ProvingKey, vk groth16.VerifyingKey, err error) {
	_, err = InitPhase1("Phase1_1", power)
	if err != nil {
		return pk, vk, err
	}
	// All members build and verify contributions for phase1
	for i := 1; i < nContributionsPhase1; i++ {
		prepath := "Phase1_" + strconv.Itoa(i)
		nextPath := "Phase1_" + strconv.Itoa(i+1)
		_, _, err := ContributePhase1(prepath, nextPath)
		if err != nil {
			return pk, vk, err
		}
	}
	evals, srs1, _, err := InitPhase2(ccs, "Phase1_"+strconv.Itoa(nContributionsPhase1), "Phase2_1")
	if err != nil {
		return pk, vk, err
	}
	// All members build and verify contributions for phase2
	for i := 1; i < nContributionsPhase2; i++ {
		prepath := "Phase2_" + strconv.Itoa(i)
		nextPath := "Phase2_" + strconv.Itoa(i+1)
		_, _, err := ContributePhase2(prepath, nextPath)
		if err != nil {
			panic(err)
		}
	}
	srs2, err := ReadPhase2FromFile("Phase2_" + strconv.Itoa(nContributionsPhase1))
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
	}
	// Extract the proving and verifying keys
	pk, vk = mpcsetup.ExtractKeys(&srs1, &srs2, &evals, ccs.GetNbConstraints())
	return pk, vk, nil
}
