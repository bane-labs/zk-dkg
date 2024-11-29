package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

type AESGCM256Wrapper struct {
	Key          [32]uints.U8
	PlainChunks  []uints.U8
	Iv           [12]uints.U8      `gnark:",public"`
	ChunkIndex   frontend.Variable `gnark:",public"`
	CipherChunks []uints.U8        `gnark:",public"`
}

// Define declares the circuit's constraints
func (circuit *AESGCM256Wrapper) Define(api frontend.API) error {
	aes := NewAES256(api)
	gcm := NewGCM256(api, &aes)
	// Verify AES-GCM of chunks
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

// AES-GCM encryption
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
		// Check ciphertext to plaintext constraints
		for i := 0; i < 16; i++ {
			gcm.api.AssertIsEqual(ctBlock[i].Val, ct[i].Val)
		}
	}
}

// Required for AES-GCM
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
		// Little endian order chunk parsing from back to front
		out[remain] = uints.U8{Val: gcm.api.FromBinary(bits[start : start+8]...)}
		remain += 1
	}

	return out
}

// Required for plaintext xor encrypted counter blocks
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
