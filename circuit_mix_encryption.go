package circom

import (
	"fmt"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	zksha3 "github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

type MixEncryptionWrapper[T1, S1, T2, S2 emulated.FieldParams] struct {
	SmallR emulated.Element[S1]        `gnark:",secret"`
	BigR   sw_emulated.AffinePoint[T1] `gnark:",secret"`
	Pub    sw_emulated.AffinePoint[T1] `gnark:",secret"`
	RPub   sw_emulated.AffinePoint[T1] `gnark:",secret"`

	PlainChunks  []frontend.Variable   `gnark:",secret"`
	Iv           [12]frontend.Variable `gnark:",secret"`
	ChunkIndex   frontend.Variable     `gnark:",secret"`
	CipherChunks []frontend.Variable   `gnark:",secret"`

	SmallFi emulated.Element[S2]        `gnark:",secret"`
	Fi      sw_emulated.AffinePoint[T2] `gnark:",secret"`
	//make a hash =(input1,input2.....) to reduce public input counts
	AllHash []frontend.Variable `gnark:",public"`
}

func (c *MixEncryptionWrapper[T1, S1, T2, S2]) Define(api frontend.API) error {
	//encrypt
	encryption := NewMixEncryption[T1, S1, T2, S2](api)
	rawPubInputs, err := encryption.Encrypt(api, c.PlainChunks, c.CipherChunks, c.Iv, c.SmallR, c.BigR, c.Pub, c.RPub, c.ChunkIndex, c.SmallFi, c.Fi)
	fmt.Println("inside length:", len(rawPubInputs))
	if err != nil {
		return err
	}
	mc, err := zksha3.New256(api)
	mc.Write(rawPubInputs)
	result := mc.Sum()

	for i := 0; i < len(result); i++ {
		api.AssertIsEqual(result[i].Val, c.AllHash[i])
	}
	return nil
}

func variableToU8(in []frontend.Variable, nbBits int) []uints.U8 {
	out := make([]uints.U8, 2*nbBits)
	for i := 0; i < len(out); i++ {
		out[i] = uints.U8{Val: in[i]}
	}
	return out
}

func NewMixEncryption[T1, S1, T2, S2 emulated.FieldParams](api frontend.API) MixEncryption[T1, S1, T2, S2] {
	return MixEncryption[T1, S1, T2, S2]{api: api}
}

type MixEncryption[T1, S1, T2, S2 emulated.FieldParams] struct {
	api frontend.API
}

func (me *MixEncryption[T1, S1, T2, S2]) Encrypt(api frontend.API, PlainChunks, CipherChunks []frontend.Variable, Iv [12]frontend.Variable, SmallR emulated.Element[S1], BigR, Pub, RPub sw_emulated.AffinePoint[T1], ChunkIndex frontend.Variable, SmallFi emulated.Element[S2], Fi sw_emulated.AffinePoint[T2]) (rawPubInputs []uints.U8, err error) {

	PlainChunksBytes := make([]uints.U8, len(PlainChunks))
	for i := 0; i < len(PlainChunks); i++ {
		PlainChunksBytes[i] = uints.U8{Val: PlainChunks[i]}
	}
	CiphertextBytes := make([]uints.U8, len(CipherChunks))
	for i := 0; i < len(CipherChunks); i++ {
		CiphertextBytes[i] = uints.U8{Val: CipherChunks[i]}
	}
	IV := [12]uints.U8{}
	for i := 0; i < len(Iv); i++ {
		IV[i] = uints.U8{Val: Iv[i]}
	}

	cr, err := sw_emulated.New[T1, S1](api, sw_emulated.GetCurveParams[T1]())
	if err != nil {
		return nil, err
	}
	//check BigR=rG
	cr.AssertIsOnCurve(&BigR)
	api.Println("R check on curve ok")
	BR := cr.ScalarMulBase(&SmallR)
	cr.AssertIsEqual(BR, &BigR)
	api.Println("R =rG check ok")
	//check pub
	cr.AssertIsOnCurve(&Pub)
	api.Println("Pub check on curve ok")
	//check RPub
	cr.AssertIsOnCurve(&RPub)
	api.Println("RPub check on curve ok")
	RPb := cr.ScalarMul(&Pub, &SmallR)
	cr.AssertIsEqual(RPb, &RPub)
	api.Println("RPub =rPub check ok")
	//generate key=hash(RPub)
	nbBits := 8 * ((fp.Modulus().BitLen() + 7) / 8)
	rawRpub := make([]uints.U8, 2*nbBits)
	raw := cr.MarshalG1(RPub)
	for i := range raw {
		rawRpub[i] = uints.U8{Val: raw[i]}
	}
	hasher, err := zksha3.New256(api)
	if err != nil {
		return nil, fmt.Errorf("hash function unknown ")
	}
	hasher.Write(rawRpub)
	expected := hasher.Sum()
	key := [32]uints.U8{}
	for j := range key {
		key[j] = expected[j]
	}
	api.Println("key generate ok")
	//check Fi=fiG
	cr2, err := sw_emulated.New[T2, S2](api, sw_emulated.GetCurveParams[T2]())
	if err != nil {
		return nil, err
	}
	cr2.AssertIsOnCurve(&Fi)
	F := cr2.ScalarMulBase(&SmallFi)
	cr2.AssertIsEqual(F, &Fi)
	api.Println("Fi=fiG check ok")
	//check aes process

	aes := NewAES256(api)
	gcm := NewGCM256(api, &aes)
	gcm.Assert(key, IV, ChunkIndex, PlainChunksBytes, CiphertextBytes)
	api.Println("aes check ok")

	//check smallFi==m
	f, err := emulated.NewField[S2](api)
	if err != nil {
		return nil, err
	}
	smallFiBits := f.ToBits(&SmallFi)
	var plainBits []frontend.Variable
	for i := range PlainChunksBytes {
		chunkBits := bits.ToBinary(api, PlainChunksBytes[len(PlainChunksBytes)-i-1].Val, bits.WithNbDigits(8))
		plainBits = append(plainBits, chunkBits...)
	}
	if len(plainBits) != len(smallFiBits) {
		return nil, fmt.Errorf("mismatch length: %d != %d", len(plainBits), len(smallFiBits))
	}
	for i := range plainBits {
		api.AssertIsEqual(plainBits[i], smallFiBits[i])
	}
	//compute raw pub inputs =(pub1,pub2.....)
	rawBigR := cr.MarshalG1(BigR)
	rawPub := cr.MarshalG1(Pub)
	rawFi := cr2.MarshalG1(Fi)
	nbBits1 := 8 * ((fp.Modulus().BitLen() + 7) / 8)
	nbBits2 := 8 * ((fr_bls12381.Modulus().BitLen() + 7) / 8)
	rawBigR_u8 := variableToU8(rawBigR, nbBits1)
	rawPub_U8 := variableToU8(rawPub, nbBits1)
	rawFi_u8 := variableToU8(rawFi, nbBits2)
	length := len(rawBigR_u8) + len(rawPub_U8) + len(rawFi_u8) + len(Iv) + 1 + len(CipherChunks)
	rawPubInputs = make([]uints.U8, length)

	for i := range rawBigR_u8 {
		rawPubInputs[i] = rawBigR_u8[i]
	}
	for i := range rawPub_U8 {
		rawPubInputs[len(rawBigR_u8)+i] = rawPub_U8[i]
	}
	for i := range rawFi_u8 {
		rawPubInputs[len(rawBigR_u8)+len(rawPub_U8)+i] = rawFi_u8[i]
	}

	for i := range Iv {
		rawPubInputs[len(rawBigR_u8)+len(rawPub_U8)+len(rawFi_u8)+i] = uints.U8{Val: Iv[i]}
	}
	rawPubInputs[len(rawBigR_u8)+len(rawPub_U8)+len(rawFi_u8)+len(Iv)] = uints.U8{Val: ChunkIndex}
	for i := range CipherChunks {
		rawPubInputs[len(rawBigR_u8)+len(rawPub_U8)+len(rawFi_u8)+len(Iv)+1+i] = uints.U8{Val: CipherChunks[i]}
	}
	return
}
