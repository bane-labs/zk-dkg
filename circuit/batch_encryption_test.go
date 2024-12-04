package circuit

import (
	"math/rand"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

func TestBatchEncryptionCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	// To demo send N fragements to N nodes, N=batch
	var batch = 2
	// Generate node private key
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	// Computing public key
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
	// Generate fragements and assigment
	fisBytes, fisInts, bigFis, nonces, encryptedFis, rs, bigRs := PrepareEncryptedKeyShares(pubKeys, fis)
	_, circuit, assignment, err := ComputeMultipleKeyShareEncryptionAssignment(batch, pubKeys, rs, bigRs, fisBytes, fisInts, bigFis, encryptedFis, nonces)
	assert.NoError(err)
	err = test.IsSolved(&circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
