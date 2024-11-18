package circom

import (
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	zksha3 "github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

type BatchEncryptionWrapper[T1, S1, T2, S2 emulated.FieldParams] struct {
	Account      []AccountConstraints[T1, S1, T2, S2] `gnark:",secret"`
	CommentsHash []frontend.Variable                  `gnark:",public"`
}

type AccountConstraints[T1, S1, T2, S2 emulated.FieldParams] struct {
	SmallR emulated.Element[S1]
	BigR   sw_emulated.AffinePoint[T1]
	Pub    sw_emulated.AffinePoint[T1]
	RPub   sw_emulated.AffinePoint[T1]

	PlainChunks  []frontend.Variable
	Iv           [12]frontend.Variable
	ChunkIndex   frontend.Variable
	CipherChunks []frontend.Variable

	SmallFi emulated.Element[S2]
	Fi      sw_emulated.AffinePoint[T2]
}

func (c *BatchEncryptionWrapper[T1, S1, T2, S2]) Define(api frontend.API) error {
	rawPubInputsbefore := make([]uints.U8, 0)
	for i := 0; i < len(c.Account); i++ {
		//prepare data
		Account := c.Account[i]
		SmallR := Account.SmallR
		BigR := Account.BigR
		Pub := Account.Pub
		RPub := Account.RPub
		PlainChunks := Account.PlainChunks[:]
		Iv := Account.Iv
		ChunkIndex := Account.ChunkIndex
		CipherChunks := Account.CipherChunks[:]
		SmallFi := Account.SmallFi
		Fi := Account.Fi
		//encrypt
		encryption := NewMixEncryption[T1, S1, T2, S2](api)
		rawPubInputs, err := encryption.Encrypt(api, PlainChunks, CipherChunks, Iv, SmallR, BigR, Pub, RPub, ChunkIndex, SmallFi, Fi)
		if err != nil {
			return err
		}
		//compute raw pub inputs
		rawPubInputsbefore = append(rawPubInputsbefore, rawPubInputs...)

		/*		length := len(rawPubInputsbefore) + len(rawPubInputs)
				temp := make([]uints.U8, length)
				for j := range rawPubInputsbefore {
					temp[j] = rawPubInputsbefore[j]
				}
				for k := range rawPubInputs {
					temp[len(rawPubInputsbefore)+k] = rawPubInputs[k]
				}
				rawPubInputsbefore = temp*/
	}
	//compute and check command hash
	//compute command hash
	mc, _ := zksha3.New256(api)
	mc.Write(rawPubInputsbefore)
	result := mc.Sum()
	//check command hash
	for i := 0; i < len(result); i++ {
		api.AssertIsEqual(result[i].Val, c.CommentsHash[i])
	}
	return nil
}

func GetCommentsHash[T1, S1, T2, S2 emulated.FieldParams](api frontend.API, CipherChunks []frontend.Variable, Iv [12]frontend.Variable, BigR, Pub sw_emulated.AffinePoint[T1], ChunkIndex frontend.Variable, Fi sw_emulated.AffinePoint[T2]) []uints.U8 {
	//check AllHash =(pub1,pub2.....)
	cr, err := sw_emulated.New[T1, S1](api, sw_emulated.GetCurveParams[T1]())
	if err != nil {
		panic(err)
	}
	cr2, err := sw_emulated.New[T2, S2](api, sw_emulated.GetCurveParams[T2]())
	if err != nil {
		panic(err)
	}
	rawBigR := cr.MarshalG1(BigR)
	rawPub := cr.MarshalG1(Pub)
	rawFi := cr2.MarshalG1(Fi)
	nbBits1 := 8 * ((fp.Modulus().BitLen() + 7) / 8)
	nbBits2 := 8 * ((fr_bls12381.Modulus().BitLen() + 7) / 8)
	rawBigR_u8 := variableToU8(rawBigR, nbBits1)
	rawPub_U8 := variableToU8(rawPub, nbBits1)
	rawFi_u8 := variableToU8(rawFi, nbBits2)
	length := len(rawBigR_u8) + len(rawPub_U8) + len(rawFi_u8) + len(Iv) + 1 + len(CipherChunks)
	rawPubInputs := make([]uints.U8, length)

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
	return rawPubInputs
}
