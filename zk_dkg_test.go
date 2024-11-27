package zkdkg

import (
	"crypto/sha256"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"strconv"
	"testing"
	"time"

	"math/rand"

	"github.com/bane-labs/zk-dkg/circuit"
	"github.com/bane-labs/zk-dkg/helper"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

func TestBatchEncryptionByMPC(t *testing.T) {
	// To demo send N fragements to N nodes, N=batch
	var batch = 7
	// Generate node private key
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	// Compute public key
	fis := make([]fr_bls12381.Element, batch)
	PubKeys := make([]ecies.PublicKey, batch)
	for i := 0; i < batch; i++ {
		key, err := ecies.GenerateKey(rand, crypto.S256(), nil)
		if err != nil {
			panic(err)
		}
		PubKeys[i] = key.PublicKey
		var fi fr_bls12381.Element
		fi.SetRandom()
		fis[i] = fi
	}
	// Generate fragements and assigment and proof
	fiBytes, sfi, bfi, nonce, ctt, rs, rb := circuit.BatchGenerateEncryptRandomFragementKey(PubKeys, fis)
	// There are two ways to compute a proof
	// 1) From an existing MPC file
	phase1Path := "Phase1_" + strconv.Itoa(3)
	phase2Path := "Phase2_" + strconv.Itoa(3)
	vk, proof, witness, err := BatchGenerateProof(phase1Path, phase2Path, PubKeys, rs, rb, fiBytes, sfi, bfi, ctt, nonce)
	// 2) From a new MPC file
	/*	css, _, assignment, err := BatchComputingAssignment(batch, PubKeys, rs, rb, fiBytes, sfi, bfi, ctt, nonce)
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
	// Verify proof
	err = groth16.Verify(proof, &vk, publicWitness.Vector().(fr_bn254.Vector), backend.WithVerifierHashToFieldFunction(sha256.New()))
	if err != nil {
		t.Fatalf(err.Error())
	}
	// Export solidity contract
	helper.ExportContract(vk)
	// Output verify data
	data := helper.GetOutputData(proof)
	data.Printf()
}
