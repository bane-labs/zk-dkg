package circuit

import (
	"math/rand"
	"testing"
	"time"

	"github.com/bane-labs/zk-dkg/encryption"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"golang.org/x/crypto/sha3"
)

// AES-GCM testing
func Test_AESGCM256_Circuit(t *testing.T) {
	assert := test.NewAssert(t)
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	privKey, err := ecies.GenerateKey(rand, crypto.S256(), nil)
	if err != nil {
		return
	}
	var px fp.Element
	px.SetInterface(privKey.PublicKey.X)
	var py fp.Element
	py.SetInterface(privKey.PublicKey.Y)
	Pub := secp256k1.G1Affine{
		X: px,
		Y: py,
	}
	RawKey := Pub.RawBytes()
	m := RawKey[:]
	M_bytes := make([]uints.U8, len(m))
	for i := 0; i < len(m); i++ {
		M_bytes[i] = uints.U8{Val: m[i]}
	}
	hasher := sha3.New256()
	hasher.Write(RawKey[:])
	expected := hasher.Sum(nil)
	keyBytes := [32]uints.U8{}
	for i := 0; i < len(keyBytes); i++ {
		keyBytes[i] = uints.U8{Val: expected[i]}
	}
	ciphertext, nonce := encryption.AESGcmEncrypt(expected[:], m)
	Ciphertext_bytes := make([]uints.U8, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		Ciphertext_bytes[i] = uints.U8{Val: ciphertext[i]}
	}
	nonce_bytes := [12]uints.U8{}
	for i := 0; i < len(nonce); i++ {
		nonce_bytes[i] = uints.U8{Val: nonce[i]}
	}
	circuit := AESGCM256Wrapper{
		PlainChunks:  make([]uints.U8, len(M_bytes)),
		CipherChunks: make([]uints.U8, len(Ciphertext_bytes)),
	}
	witness := AESGCM256Wrapper{
		Key:          keyBytes,
		PlainChunks:  M_bytes,
		Iv:           nonce_bytes,
		ChunkIndex:   2,
		CipherChunks: Ciphertext_bytes,
	}
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
