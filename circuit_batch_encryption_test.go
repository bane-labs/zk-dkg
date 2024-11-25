package circom

import (
	"crypto/sha256"
	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"math/rand"
	"strconv"
	"testing"
	"time"
)

func Test_BatchEncryption_Circuit(t *testing.T) {
	//to demo send N fragements to N nodes,N=batch
	var batch = 2
	//generate node private key
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	//computing pub key
	PubKeys := make([]ecies.PublicKey, batch)
	for i := 0; i < batch; i++ {
		key, err := ecies.GenerateKey(rand, crypto.S256(), nil)
		if err != nil {
			panic(err)
		}
		PubKeys[i] = key.PublicKey
	}
	//generate fragements and assigment
	fiBytes, sfi, bfi, nonce, ctt, rs, rb := BatchGenerateEncryptFragementKey(PubKeys)
	_, circuit, assignment, err := BatchComputingAssignment(batch, PubKeys, rs, rb, fiBytes, sfi, bfi, ctt, nonce)
	if err != nil {
		panic(err)
	}
	err = test.IsSolved(&circuit, assignment, ecc.BN254.ScalarField())
	assert := test.NewAssert(t)
	assert.NoError(err)
}

func TestBatchEncryptionByMPC(t *testing.T) {
	//to demo send N fragements to N nodes,N=batch
	var batch = 7
	//generate node private key
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	//computing pub key
	PubKeys := make([]ecies.PublicKey, batch)
	for i := 0; i < batch; i++ {
		key, err := ecies.GenerateKey(rand, crypto.S256(), nil)
		if err != nil {
			panic(err)
		}
		PubKeys[i] = key.PublicKey
	}
	//generate fragements and assigment and proof
	fiBytes, sfi, bfi, nonce, ctt, rs, rb := BatchGenerateEncryptFragementKey(PubKeys)
	//computing proof 2 way
	//1)from existed mpc file
	phase1Path := "Phase1_" + strconv.Itoa(3)
	phase2Path := "Phase2_" + strconv.Itoa(3)
	vk, proof, witness, err := BatchGenerateProof(phase1Path, phase2Path, PubKeys, rs, rb, fiBytes, sfi, bfi, ctt, nonce)
	//2)from a new mpc file
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
	//verify proof
	err = groth16.Verify(proof, &vk, publicWitness.Vector().(fr_bn254.Vector), backend.WithVerifierHashToFieldFunction(sha256.New()))
	if err != nil {
		t.Fatalf(err.Error())
	}
	//export solidity contract
	ExportContract(vk)
	//output verify data
	data := GetOutputData(proof)
	data.printf()
}
