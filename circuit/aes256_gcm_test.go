package circuit

import (
	"math/rand"
	"testing"
	"time"

	"github.com/bane-labs/zk-dkg/encryption"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"golang.org/x/crypto/sha3"
)

// AES-GCM testing
func TestAESGCM256Circuit(t *testing.T) {
	assert := test.NewAssert(t)
	// Generate a random secp256k1 key
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	privKey, err := ecies.GenerateKey(rand, crypto.S256(), nil)
	assert.NoError(err)
	// Get corresponding pub key bytes for AES
	pubKey := new(secp256k1.G1Affine)
	pubKey.X.SetBigInt(privKey.PublicKey.X)
	pubKey.Y.SetBigInt(privKey.PublicKey.Y)
	// Convert pub key to bytes
	pubKeyBytes := pubKey.RawBytes()
	m := pubKeyBytes[:]
	mBytes := make([]uints.U8, len(m))
	for i := 0; i < len(m); i++ {
		mBytes[i] = uints.U8{Val: m[i]}
	}
	// Hash to an AES key
	hasher := sha3.New256()
	hasher.Write(pubKeyBytes[:])
	expected := hasher.Sum(nil)
	keyBytes := [32]uints.U8{}
	for i := 0; i < len(keyBytes); i++ {
		keyBytes[i] = uints.U8{Val: expected[i]}
	}
	// Prepare circuit and witness
	ciphertext, nonce, err := encryption.AESGCMEncrypt(expected[:], m)
	assert.NoError(err)
	cBytes := make([]uints.U8, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		cBytes[i] = uints.U8{Val: ciphertext[i]}
	}
	nBytes := [12]uints.U8{}
	for i := 0; i < len(nonce); i++ {
		nBytes[i] = uints.U8{Val: nonce[i]}
	}
	circuit := AESGCM256Wrapper{
		PlainChunks:  make([]uints.U8, len(mBytes)),
		CipherChunks: make([]uints.U8, len(cBytes)),
	}
	witness := AESGCM256Wrapper{
		Key:          keyBytes,
		PlainChunks:  mBytes,
		Iv:           nBytes,
		ChunkIndex:   2,
		CipherChunks: cBytes,
	}
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
