package zkdkg

import (
	"crypto/sha256"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/bane-labs/zk-dkg/circuit"
	"github.com/bane-labs/zk-dkg/helper"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

func TestBatchEncryptionWithMPC(t *testing.T) {
	assert := test.NewAssert(t)
	// To demo send N fragements to N nodes, N=batch
	var batch = 7
	// Generate node private key
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	// Compute public key
	fis := make([]fr_bls12381.Element, batch)
	pubKeys := make([]ecies.PublicKey, batch)
	for i := 0; i < batch; i++ {
		key, err := ecies.GenerateKey(rand, crypto.S256(), nil)
		assert.NoError(err)
		pubKeys[i] = key.PublicKey
		var fi fr_bls12381.Element
		fi.SetRandom()
		fis[i] = fi
	}
	// Generate fragements and assigment and proof
	fisBytes, fisInts, bigFis, nonces, encryptedFis, rs, bigRs := circuit.PrepareEncryptedKeyShares(pubKeys, fis)
	// There are two ways to compute a proof
	// 1) From an existing MPC file
	phase1Path := "Phase1_" + strconv.Itoa(3)
	phase2Path := "Phase2_" + strconv.Itoa(3)
	vk, proof, witness, err := ProveMultipleKeyShareEncryption(phase1Path, phase2Path, pubKeys, rs, bigRs, fisBytes, fisInts, bigFis, encryptedFis, nonces)
	assert.NoError(err)
	// 2) From a new MPC file
	/*	css, _, assignment, err := circuit.BatchComputingAssignment(batch, pubKeys, rs, rb, fiBytes, sfi, bfi, ctt, nonce)
		assert.NoError(err)
		_, vk, proof, witness, err := computingProof2(css, assignment)
		assert.NoError(err)*/
	publicWitness, err := witness.Public()
	assert.NoError(err)
	// Verify proof
	err = groth16.Verify(proof, &vk, publicWitness.Vector().(fr_bn254.Vector), backend.WithVerifierHashToFieldFunction(sha256.New()))
	assert.NoError(err)
	// Export solidity contract
	helper.ExportContract(vk)
	// Output verify data
	data := helper.GetOutputData(proof)
	data.Printf()
}
