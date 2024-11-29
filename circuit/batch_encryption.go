package circuit

import (
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
	BigFi   sw_emulated.AffinePoint[T2]
}

func (c *BatchEncryptionWrapper[T1, S1, T2, S2]) Define(api frontend.API) error {
	pubInputs := make([]uints.U8, 0)
	for i := 0; i < len(c.Account); i++ {
		// Prepare data
		account := c.Account[i]
		r := account.SmallR
		bigR := account.BigR
		pub := account.Pub
		rPub := account.RPub
		plainChunks := account.PlainChunks[:]
		iv := account.Iv
		chunkIndex := account.ChunkIndex
		cipherChunks := account.CipherChunks[:]
		fi := account.SmallFi
		bigFi := account.BigFi
		// Encrypt
		encryption := NewECIES[T1, S1, T2, S2](api)
		pis, err := encryption.Encrypt(api, plainChunks, cipherChunks, iv, r, bigR, pub, rPub, chunkIndex, fi, bigFi)
		if err != nil {
			return err
		}
		// Compute raw pub inputs
		pubInputs = append(pubInputs, pis...)
	}
	// Compute comments hash
	mc, _ := zksha3.New256(api)
	mc.Write(pubInputs)
	result := mc.Sum()
	// Check comments hash
	for i := 0; i < len(result); i++ {
		api.AssertIsEqual(result[i].Val, c.CommentsHash[i])
	}
	return nil
}
