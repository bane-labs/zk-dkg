package circuit

import (
	"fmt"
	"slices"

	fp_secp "github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

// ECIESWrapper is the circuit for ECIES encryption
type ECIESWrapper[T1, S1, T2, S2 emulated.FieldParams] struct {
	SmallR emulated.Element[S1]        `gnark:",secret"`
	BigR   sw_emulated.AffinePoint[T1] `gnark:",secret"`
	Pub    sw_emulated.AffinePoint[T1] `gnark:",secret"`
	RPub   sw_emulated.AffinePoint[T1] `gnark:",secret"`

	Iv           [12]frontend.Variable `gnark:",secret"`
	ChunkIndex   frontend.Variable     `gnark:",secret"`
	CipherChunks []frontend.Variable   `gnark:",secret"`

	SmallFi emulated.Element[S2]        `gnark:",secret"`
	Fi      sw_emulated.AffinePoint[T2] `gnark:",secret"`
	// Make a hash=(input1,input2.....) to reduce public input counts
	PubInputHash []frontend.Variable `gnark:",public"`
}

// Define declares the circuit's constraints
func (c *ECIESWrapper[T1, S1, T2, S2]) Define(api frontend.API) error {
	// Encrypt
	encryption := NewECIES[T1, S1, T2, S2](api)
	rawPubInputs, err := encryption.Encrypt(c.CipherChunks, c.Iv, c.SmallR, c.BigR, c.Pub, c.RPub, c.ChunkIndex, c.SmallFi, c.Fi)
	if err != nil {
		return err
	}
	mc, err := sha2.New(api)
	if err != nil {
		return err
	}
	mc.Write(rawPubInputs)
	result := mc.Sum()

	for i := 0; i < len(result); i++ {
		api.AssertIsEqual(result[i].Val, c.PubInputHash[i])
	}
	return nil
}

// bigEndianBitsToBytes converts a big-endian marshalled bit array to a byte array in uints.U8s.
func bigEndianBitsToBytes(api frontend.API, in []frontend.Variable) []uints.U8 {
	if len(in)%8 != 0 {
		panic(fmt.Errorf("invalid bit length: %d, must be a multiple of 8", len(in)))
	}
	// Reverse to get little-endian
	data := make([]frontend.Variable, len(in))
	copy(data, in)
	slices.Reverse(data)
	// Transform bits to bytes
	out := make([]uints.U8, len(data)/8)
	for i := 0; i < len(out); i++ {
		out[i] = uints.U8{Val: api.FromBinary(data[i*8 : (i+1)*8]...)}
	}
	// Reverse back to big-endian
	slices.Reverse(out)
	return out
}

func NewECIES[T1, S1, T2, S2 emulated.FieldParams](api frontend.API) ECIES[T1, S1, T2, S2] {
	return ECIES[T1, S1, T2, S2]{api: api}
}

type ECIES[T1, S1, T2, S2 emulated.FieldParams] struct {
	api frontend.API
}

// Encrypt encrypts the plaintext using ECIES
func (ecies *ECIES[T1, S1, T2, S2]) Encrypt(cipherChunks []frontend.Variable, iv [12]frontend.Variable, r emulated.Element[S1], bigR, pub, rPub sw_emulated.AffinePoint[T1], chunkIndex frontend.Variable, fi emulated.Element[S2], bigFi sw_emulated.AffinePoint[T2]) ([]uints.U8, error) {
	api := ecies.api
	f, err := emulated.NewField[S2](api)
	if err != nil {
		return nil, err
	}
	shareBits := f.ToBits(&fi) // Little-endian, in reverse
	for len(shareBits)%8 != 0 {
		shareBits = append(shareBits, 0) // Fill in 0
	}
	pBytes := make([]uints.U8, 0)
	for i := 0; i < len(shareBits)/8; i++ {
		index := len(shareBits)/8 - 1 - i
		pBytes = append(pBytes, uints.U8{Val: api.FromBinary(shareBits[index*8 : (index+1)*8]...)})

	}
	cBytes := make([]uints.U8, len(cipherChunks))
	for i := 0; i < len(cipherChunks); i++ {
		cBytes[i] = uints.U8{Val: cipherChunks[i]}
	}
	ivBytes := [12]uints.U8{}
	for i := 0; i < len(iv); i++ {
		ivBytes[i] = uints.U8{Val: iv[i]}
	}

	cr, err := sw_emulated.New[T1, S1](api, sw_emulated.GetCurveParams[T1]())
	if err != nil {
		return nil, err
	}
	// Check bigR=rG
	cr.AssertIsOnCurve(&bigR)
	cr.AssertIsEqual(cr.ScalarMulBase(&r), &bigR)
	// Check pub
	cr.AssertIsOnCurve(&pub)
	// Check rPub
	cr.AssertIsOnCurve(&rPub)
	cr.AssertIsEqual(cr.ScalarMul(&pub, &r), &rPub)
	// Generate key=hash(rPub)
	nbBits := 8 * ((fp_secp.Modulus().BitLen() + 7) / 8)
	rawRpub := make([]uints.U8, 2*nbBits)
	raw := cr.MarshalG1(rPub)
	for i := range raw {
		rawRpub[i] = uints.U8{Val: raw[i]}
	}
	hasher, err := sha3.New256(api)
	if err != nil {
		return nil, err
	}
	hasher.Write(rawRpub)
	expected := hasher.Sum()
	key := [32]uints.U8{}
	for j := range key {
		key[j] = expected[j]
	}
	// Check Fi=fiG
	cr2, err := sw_emulated.New[T2, S2](api, sw_emulated.GetCurveParams[T2]())
	if err != nil {
		return nil, err
	}
	cr2.AssertIsOnCurve(&bigFi)
	cr2.AssertIsEqual(cr2.ScalarMulBase(&fi), &bigFi)
	// Check aes process
	aes := NewAES256(api)
	gcm := NewGCM256(api, &aes)
	gcm.Assert(key, ivBytes, chunkIndex, pBytes, cBytes)

	// Compute pubInputs=(pub1,pub2.....)
	rawBigR := cr.MarshalG1(bigR)
	rawPub := cr.MarshalG1(pub)
	rawBigFi := cr2.MarshalG1(bigFi)
	bigRU8s := bigEndianBitsToBytes(api, rawBigR)
	pubU8s := bigEndianBitsToBytes(api, rawPub)
	bigFiU8s := bigEndianBitsToBytes(api, rawBigFi)
	length := len(bigRU8s) + len(pubU8s) + len(bigFiU8s) + len(iv) + 1 + len(cipherChunks)
	pubInputs := make([]uints.U8, length)
	for i := range bigRU8s {
		pubInputs[i] = bigRU8s[i]
	}
	for i := range pubU8s {
		pubInputs[len(bigRU8s)+i] = pubU8s[i]
	}
	for i := range bigFiU8s {
		pubInputs[len(bigRU8s)+len(pubU8s)+i] = bigFiU8s[i]
	}
	for i := range iv {
		pubInputs[len(bigRU8s)+len(pubU8s)+len(bigFiU8s)+i] = uints.U8{Val: iv[i]}
	}
	pubInputs[len(bigRU8s)+len(pubU8s)+len(bigFiU8s)+len(iv)] = uints.U8{Val: chunkIndex}
	for i := range cipherChunks {
		pubInputs[len(bigRU8s)+len(pubU8s)+len(bigFiU8s)+len(iv)+1+i] = uints.U8{Val: cipherChunks[i]}
	}
	return pubInputs, nil
}
