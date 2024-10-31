/*
Copyright 2023 Jan Lauinger

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package circom

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"golang.org/x/crypto/sha3"
	"math/rand"
	"testing"
	"time"
)

// AES gcm testing
func Test_AESGCM256_Circuit(t *testing.T) {

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
		px,
		py,
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
	ciphertext, nonce := AesGcmEncrypt(expected[:], m)
	Ciphertext_bytes := make([]uints.U8, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		Ciphertext_bytes[i] = uints.U8{Val: ciphertext[i]}
	}
	nonce_bytes := [12]uints.U8{}
	for i := 0; i < len(nonce); i++ {
		nonce_bytes[i] = uints.U8{Val: nonce[i]}
	}
	circuit := Circuit_GCM256Wrapper{
		PlainChunks:  make([]uints.U8, len(M_bytes)),
		CipherChunks: make([]uints.U8, len(Ciphertext_bytes)),
	}
	witness := Circuit_GCM256Wrapper{
		Key:          keyBytes,
		PlainChunks:  M_bytes,
		Iv:           nonce_bytes,
		ChunkIndex:   2,
		CipherChunks: Ciphertext_bytes,
	}
	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
