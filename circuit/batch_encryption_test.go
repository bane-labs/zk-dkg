package circuit

import (
	"math/rand"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

func TestBatchEncryptionCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	// To demo send N fragements to N nodes, N=batch
	var batch = 1
	// Generate node private key
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	// Computing public key
	fis := make([]*fr_bls12381.Element, batch)
	pubKeys := make([]*ecies.PublicKey, batch)
	for i := 0; i < batch; i++ {
		key, err := ecies.GenerateKey(rand, crypto.S256(), nil)
		assert.NoError(err)
		pubKeys[i] = &key.PublicKey
		fi := new(fr_bls12381.Element)
		_, err = fi.SetRandom()
		assert.NoError(err)
		fis[i] = fi
	}
	// Generate fragements and assigment
	fisBytes, fisInts, bigFis, nonces, encryptedFis, rs, bigRs, err := PrepareEncryptedKeyShares(pubKeys, fis)
	assert.NoError(err)
	circuit := BatchEncryptionWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		Parameters: make([]ECIESParameters[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], batch),
		SumHash:    make([]frontend.Variable, 32),
	}
	for i := 0; i < batch; i++ {
		circuit.Parameters[i].PlainChunks = make([]frontend.Variable, len(fisBytes[i]))
		circuit.Parameters[i].CipherChunks = make([]frontend.Variable, len(encryptedFis[i]))
	}
	assignment, _ := ComputeMultipleKeyShareEncryptionAssignment(batch, pubKeys, rs, bigRs, fisBytes, fisInts, bigFis, encryptedFis, nonces)
	err = test.IsSolved(&circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
