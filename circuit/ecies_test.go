package circuit

import (
	"math/rand"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
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
	fi := new(fr_bls12381.Element)
	_, err = fi.SetRandom()
	assert.NoError(err)
	fiBytes, fiInt, bigFi := transformKeyShare(fi)
	nonce, encryptedFi, r, bigR, err := encryptKeyShare(&privKey.PublicKey, fiBytes)
	assert.NoError(err)
	// Verify circuit
	circuit := ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		PlainChunks:  make([]frontend.Variable, len(fiBytes)),
		CipherChunks: make([]frontend.Variable, len(encryptedFi)),
		PubInputHash: make([]frontend.Variable, 32),
	}
	parameters, hashes := ComputeSingleKeyShareEncryptionAssignment(&privKey.PublicKey, r, bigR, fiBytes, fiInt, bigFi, encryptedFi, nonce)
	rawSumHash := make([]frontend.Variable, len(hashes))
	for i := 0; i < len(hashes); i++ {
		rawSumHash[i] = hashes[i]
	}
	assignment := &ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		SmallR:       parameters.SmallR,
		BigR:         parameters.BigR,
		Pub:          parameters.Pub,
		RPub:         parameters.RPub,
		PlainChunks:  parameters.PlainChunks,
		Iv:           parameters.Iv,
		ChunkIndex:   parameters.ChunkIndex,
		CipherChunks: parameters.CipherChunks,
		SmallFi:      parameters.SmallFi,
		Fi:           parameters.Fi,
		PubInputHash: rawSumHash,
	}
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
	fi := new(fr_bls12381.Element)
	_, err = fi.SetRandom()
	assert.NoError(err)
	fiBytes, fiInt, bigFi := transformKeyShare(fi)
	nonce, encryptedFi, r, bigR, err := encryptKeyShare(&privKey.PublicKey, fiBytes)
	assert.NoError(err)
	// Compute proof
	circuit := ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		PlainChunks:  make([]frontend.Variable, len(fiBytes)),
		CipherChunks: make([]frontend.Variable, len(encryptedFi)),
		PubInputHash: make([]frontend.Variable, 32),
	}
	_, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(err)
	parameters, hashes := ComputeSingleKeyShareEncryptionAssignment(&privKey.PublicKey, r, bigR, fiBytes, fiInt, bigFi, encryptedFi, nonce)
	rawSumHash := make([]frontend.Variable, len(hashes))
	for i := 0; i < len(hashes); i++ {
		rawSumHash[i] = hashes[i]
	}
	assignment := &ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		SmallR:       parameters.SmallR,
		BigR:         parameters.BigR,
		Pub:          parameters.Pub,
		RPub:         parameters.RPub,
		PlainChunks:  parameters.PlainChunks,
		Iv:           parameters.Iv,
		ChunkIndex:   parameters.ChunkIndex,
		CipherChunks: parameters.CipherChunks,
		SmallFi:      parameters.SmallFi,
		Fi:           parameters.Fi,
		PubInputHash: rawSumHash,
	}
	err = test.IsSolved(&circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)

	/*	_, vk, proof, witness, err := computingProof2(css, assignment)
		assert.NoError(err)
		publicWitness, err := witness.Public()
		assert.NoError(err)
		// Verify proof
		err = groth16.Verify(proof, vk, publicWitness.Vector().(fr_bn254.Vector))
		assert.NoError(err)
		// Export solidity contract
		helper.ExportContract(vk, "Verify.sol")*/
	// Output verify data
	//helper.GetContractInput(proof)
}
