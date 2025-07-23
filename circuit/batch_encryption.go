package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

// "DKG_BATCH_HASH_V1"
var hashDomainU8s = []uints.U8{
	uints.NewU8(0x44),
	uints.NewU8(0x4b),
	uints.NewU8(0x47),
	uints.NewU8(0x5f),
	uints.NewU8(0x42),
	uints.NewU8(0x41),
	uints.NewU8(0x54),
	uints.NewU8(0x43),
	uints.NewU8(0x48),
	uints.NewU8(0x5f),
	uints.NewU8(0x48),
	uints.NewU8(0x41),
	uints.NewU8(0x53),
	uints.NewU8(0x48),
	uints.NewU8(0x5f),
	uints.NewU8(0x56),
	uints.NewU8(0x31),
}

type BatchEncryptionWrapper[T1, S1, T2, S2 emulated.FieldParams] struct {
	Parameters []ECIESParameters[T1, S1, T2, S2] `gnark:",secret"`
	SumHash    []frontend.Variable               `gnark:",public"`
}

type ECIESParameters[T1, S1, T2, S2 emulated.FieldParams] struct {
	SmallR emulated.Element[S1]
	BigR   sw_emulated.AffinePoint[T1]
	Pub    sw_emulated.AffinePoint[T1]
	RPub   sw_emulated.AffinePoint[T1]

	Iv           [12]frontend.Variable
	ChunkIndex   frontend.Variable
	CipherChunks []frontend.Variable

	SmallFi emulated.Element[S2]
	Fi      sw_emulated.AffinePoint[T2]
}

func (c *BatchEncryptionWrapper[T1, S1, T2, S2]) Define(api frontend.API) error {
	summaryInput := make([]uints.U8, 0)
	summaryInput = append(summaryInput, hashDomainU8s...)
	summaryInput = append(summaryInput, uints.NewU8(byte(len(c.Parameters))))
	for i := 0; i < len(c.Parameters); i++ {
		// Prepare data
		account := c.Parameters[i]
		r := account.SmallR
		bigR := account.BigR
		pub := account.Pub
		rPub := account.RPub
		iv := account.Iv
		chunkIndex := account.ChunkIndex
		cipherChunks := account.CipherChunks[:]
		fi := account.SmallFi
		bigFi := account.Fi
		// Encrypt
		encryption := NewECIES[T1, S1, T2, S2](api)
		innerData, err := encryption.Encrypt(cipherChunks, iv, r, bigR, pub, rPub, chunkIndex, fi, bigFi)
		if err != nil {
			return err
		}
		innerHasher, _ := sha2.New(api)
		innerHasher.Write(innerData)
		innerHash := innerHasher.Sum()
		// Compute raw pub inputs
		summaryInput = append(summaryInput, uints.NewU8(byte(i)), uints.NewU8(byte(len(innerHash))))
		summaryInput = append(summaryInput, innerHash...)
	}
	// Compute comments hash
	summaryHasher, _ := sha2.New(api)
	summaryHasher.Write(summaryInput)
	summary := summaryHasher.Sum()
	// Check comments hash
	for i := 0; i < len(summary); i++ {
		api.AssertIsEqual(summary[i].Val, c.SumHash[i])
	}
	return nil
}
