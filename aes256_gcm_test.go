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
	"github.com/consensys/gnark/frontend"
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
type GCM256Wrapper struct {
	Key          [32]uints.U8
	PlainChunks  []uints.U8
	Iv           [12]uints.U8      `gnark:",public"`
	ChunkIndex   frontend.Variable `gnark:",public"`
	CipherChunks []uints.U8        `gnark:",public"`
}

// Define declares the circuit's constraints
func (circuit *GCM256Wrapper) Define(api frontend.API) error {
	aes := NewAES256(api)
	gcm := NewGCM256(api, &aes)
	// verify aes gcm of chunks
	gcm.Assert(circuit.Key, circuit.Iv, circuit.ChunkIndex, circuit.PlainChunks, circuit.CipherChunks)
	return nil
}

type AES interface {
	Encrypt(key [32]uints.U8, pt [16]uints.U8) [16]uints.U8
}

func NewGCM256(api frontend.API, aes AES) GCM256 {
	return GCM256{api: api, aes: aes}
}

type GCM256 struct {
	api frontend.API
	aes AES
}

// aes gcm encryption
func (gcm *GCM256) Assert(key [32]uints.U8, iv [12]uints.U8, chunkIndex frontend.Variable, plaintext, ciphertext []uints.U8) {

	inputSize := len(plaintext)
	numberBlocks := int(inputSize / 16)
	var epoch int
	for epoch = 0; epoch < numberBlocks; epoch++ {

		idx := gcm.api.Add(chunkIndex, frontend.Variable(epoch))
		eIndex := epoch * 16

		var ptBlock [16]uints.U8
		var ctBlock [16]uints.U8

		for j := 0; j < 16; j++ {
			ptBlock[j] = plaintext[eIndex+j]
			ctBlock[j] = ciphertext[eIndex+j]
		}

		ivCounter := gcm.GetIV(iv, idx)
		intermediate := gcm.aes.Encrypt(key, ivCounter)
		ct := gcm.Xor16(intermediate, ptBlock)
		// check ciphertext to plaintext constraints
		for i := 0; i < 16; i++ {
			gcm.api.AssertIsEqual(ctBlock[i].Val, ct[i].Val)
		}
	}
}

// required for aes_gcm
func (gcm *GCM256) GetIV(nonce [12]uints.U8, ctr frontend.Variable) [16]uints.U8 {

	var out [16]uints.U8
	var i int
	for i = 0; i < len(nonce); i++ {
		out[i] = nonce[i]
	}
	bits := gcm.api.ToBinary(ctr, 32)
	remain := 12
	for j := 3; j >= 0; j-- {
		start := 8 * j
		// little endian order chunk parsing from back to front
		out[remain] = uints.U8{Val: gcm.api.FromBinary(bits[start : start+8]...)}
		remain += 1
	}

	return out
}

// required for plaintext xor encrypted counter blocks
func (gcm *GCM256) Xor16(a [16]uints.U8, b [16]uints.U8) [16]uints.U8 {
	var out [16]uints.U8
	for i := 0; i < 16; i++ {
		out[i] = uints.U8{Val: gcm.variableXor(a[i].Val, b[i].Val, 8)}
	}
	return out
}

func (gcm *GCM256) variableXor(a frontend.Variable, b frontend.Variable, size int) frontend.Variable {
	bitsA := gcm.api.ToBinary(a, size)
	bitsB := gcm.api.ToBinary(b, size)
	x := make([]frontend.Variable, size)
	for i := 0; i < size; i++ {
		x[i] = gcm.api.Xor(bitsA[i], bitsB[i])
	}
	return gcm.api.FromBinary(x...)
}

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
	circuit := GCM256Wrapper{
		PlainChunks:  make([]uints.U8, len(M_bytes)),
		CipherChunks: make([]uints.U8, len(Ciphertext_bytes)),
	}
	witness := GCM256Wrapper{
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
