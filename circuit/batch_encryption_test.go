package circuit

import (
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
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
	fis := make([]fr_bls12381.Element, batch)
	PubKeys := make([]ecies.PublicKey, batch)
	for i := 0; i < batch; i++ {
		key, err := ecies.GenerateKey(rand, crypto.S256(), nil)
		assert.NoError(err)
		PubKeys[i] = key.PublicKey
		var fi fr_bls12381.Element
		fi.SetRandom()
		fis[i] = fi
	}
	// Generate fragements and assigment
	fiBytes, sfi, bfi, nonce, ctt, rs, rb := BatchGenerateEncryptRandomFragementKey(PubKeys, fis)
	_, circuit, assignment, err := BatchComputingAssignment(batch, PubKeys, rs, rb, fiBytes, sfi, bfi, ctt, nonce)
	assert.NoError(err)
	err = test.IsSolved(&circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
