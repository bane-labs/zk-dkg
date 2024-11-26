package circuit

import (
	"math/rand"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

func Test_BatchEncryption_Circuit(t *testing.T) {
	assert := test.NewAssert(t)
	// To demo send N fragements to N nodes, N=batch
	var batch = 2
	// Generate node private key
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	// Computing public key
	PubKeys := make([]ecies.PublicKey, batch)
	for i := 0; i < batch; i++ {
		key, err := ecies.GenerateKey(rand, crypto.S256(), nil)
		assert.NoError(err)
		PubKeys[i] = key.PublicKey
	}
	// Generate fragements and assigment
	fiBytes, sfi, bfi, nonce, ctt, rs, rb := BatchGenerateEncryptRandomFragementKey(PubKeys)
	_, circuit, assignment, err := BatchComputingAssignment(batch, PubKeys, rs, rb, fiBytes, sfi, bfi, ctt, nonce)
	assert.NoError(err)
	err = test.IsSolved(&circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
