package circuit

import (
	"fmt"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

// ECIESWrapper is the circuit for ECIES encryption
type ECIESWrapper[T1, S1, T2, S2 emulated.FieldParams] struct {
	R   emulated.Element[S1]        `gnark:",secret"` // Random number used in ECIES
	Pub sw_emulated.AffinePoint[T1] `gnark:",secret"` // Public key used in ECIES
	Fi  emulated.Element[S2]        `gnark:",secret"` // Key share to be encrypted in ECIES

	Iv           [12]frontend.Variable `gnark:",secret"` // Nonce for AES-GCM
	ChunkIndex   frontend.Variable     `gnark:",secret"`
	CipherChunks []frontend.Variable   `gnark:",secret"` // The encrypted key share

	PubInputHash [32]uints.U8 `gnark:",public"` // The hash of the public inputs
}

// Define declares the circuit's constraints
func (c *ECIESWrapper[T1, S1, T2, S2]) Define(api frontend.API) error {
	// Verify encryption and compute public inputs
	ecies := NewECIES[T1, S1, T2, S2](api)
	rawPubInputs, err := ecies.Encrypt(c.CipherChunks, c.Iv, c.R, c.Pub, c.ChunkIndex, c.Fi)
	if err != nil {
		return err
	}
	hasher, err := sha2.New(api)
	if err != nil {
		return err
	}
	hasher.Write(rawPubInputs)
	result := hasher.Sum()
	// Verify the hash of the public inputs
	for i := 0; i < len(result); i++ {
		api.AssertIsEqual(result[i].Val, c.PubInputHash[i].Val)
	}
	return nil
}

// bigEndianBitsToBytes converts a big-endian marshalled bit array to a byte array in uints.U8s.
func bigEndianBitsToBytes(api frontend.API, in []frontend.Variable) []uints.U8 {
	if len(in)%8 != 0 || len(in) == 0 {
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
func (ecies *ECIES[T1, S1, T2, S2]) Encrypt(cipherChunks []frontend.Variable, iv [12]frontend.Variable, r emulated.Element[S1], pub sw_emulated.AffinePoint[T1], chunkIndex frontend.Variable, fi emulated.Element[S2]) ([]uints.U8, error) {
	api := ecies.api
	f, err := emulated.NewField[S2](api)
	if err != nil {
		return nil, err
	}
	cr, err := sw_emulated.New[T1, S1](api, sw_emulated.GetCurveParams[T1]())
	if err != nil {
		return nil, err
	}
	cr2, err := sw_emulated.New[T2, S2](api, sw_emulated.GetCurveParams[T2]())
	if err != nil {
		return nil, err
	}
	// Transform inputs for encryption
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
	// Compute Fi=fi*G, as the commitment of the key share fi
	bigFi := cr2.ScalarMulBase(&fi)
	// Compute bigR=r*G, as the commitment of the random number r
	bigR := cr.ScalarMulBase(&r)
	// Compute rPub=r*pub, as the seed for AES key generation
	cr.AssertIsOnCurve(&pub)
	rPub := cr.ScalarMul(&pub, &r)
	// Generate key=hash(rPub.X, bigR)
	rawRPub := cr.MarshalG1(*rPub)
	rawBigR := cr.MarshalG1(*bigR)
	nFpBits := 32 * 8 // 32 bytes for a Secp256k1 Fp element X
	rPubXU8s := bigEndianBitsToBytes(api, rawRPub[:nFpBits])
	bigRU8s := bigEndianBitsToBytes(api, rawBigR)
	hasher, err := sha3.New256(api)
	if err != nil {
		return nil, fmt.Errorf("hash function unknown")
	}
	hasher.Write(rPubXU8s)
	hasher.Write(bigRU8s)
	key := [32]uints.U8{}
	copy(key[:], hasher.Sum())
	// Check AES result
	aes := NewAES256(api)
	gcm := NewGCM256(api, &aes)
	gcm.Assert(key, ivBytes, chunkIndex, pBytes, cBytes)
	// Compute pubInputs=(pub1,pub2.....)
	rawPub := cr.MarshalG1(pub)
	rawBigFi := cr2.MarshalG1(*bigFi)
	pubU8s := bigEndianBitsToBytes(api, rawPub)
	bigFiU8s := bigEndianBitsToBytes(api, rawBigFi)
	length := len(bigRU8s) + len(pubU8s) + len(bigFiU8s) + len(iv) + 1 + len(cipherChunks)
	pubInputs := make([]uints.U8, length)
	copy(pubInputs, bigRU8s)
	copy(pubInputs[len(bigRU8s):], pubU8s)
	copy(pubInputs[len(bigRU8s)+len(pubU8s):], bigFiU8s)
	for i := range iv {
		pubInputs[len(bigRU8s)+len(pubU8s)+len(bigFiU8s)+i] = uints.U8{Val: iv[i]}
	}
	pubInputs[len(bigRU8s)+len(pubU8s)+len(bigFiU8s)+len(iv)] = uints.U8{Val: chunkIndex}
	for i := range cipherChunks {
		pubInputs[len(bigRU8s)+len(pubU8s)+len(bigFiU8s)+len(iv)+1+i] = uints.U8{Val: cipherChunks[i]}
	}
	return pubInputs, nil
}
