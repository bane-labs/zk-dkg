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
	Fi      sw_emulated.AffinePoint[T2]
}

func (c *BatchEncryptionWrapper[T1, S1, T2, S2]) Define(api frontend.API) error {
	rawPubInputsbefore := make([]uints.U8, 0)
	for i := 0; i < len(c.Account); i++ {
		// Prepare data
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
		// Encrypt
		encryption := NewECIES[T1, S1, T2, S2](api)
		rawPubInputs, err := encryption.Encrypt(api, PlainChunks, CipherChunks, Iv, SmallR, BigR, Pub, RPub, ChunkIndex, SmallFi, Fi)
		if err != nil {
			return err
		}
		// Compute raw pub inputs
		rawPubInputsbefore = append(rawPubInputsbefore, rawPubInputs...)
	}
	// Compute and check comments hash
	// Compute comments hash
	mc, _ := zksha3.New256(api)
	mc.Write(rawPubInputsbefore)
	result := mc.Sum()
	// Check comments hash
	for i := 0; i < len(result); i++ {
		api.AssertIsEqual(result[i].Val, c.CommentsHash[i])
	}
	return nil
}
