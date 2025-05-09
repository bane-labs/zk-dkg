package circuit

import (
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark/backend/plonk"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

func TestPlonk(t *testing.T) {
	var circuit InnerCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	scs := ccs.(*cs.SparseR1CS)
	srs, srsLagrange, err := unsafekzg.NewSRS(scs)
	if err != nil {
		panic(err)
	}

	var w InnerCircuit
	w.X = 4
	w.Y = 4

	witness, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	witnessPub, err := witness.Public()
	if err != nil {
		panic(err)
	}
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		panic(err)
	}
	proof, err := plonk.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}
	err = plonk.Verify(proof, vk, witnessPub)
	if err != nil {
		panic(err)
	}
}

func TestPlonkWithMPC(t *testing.T) {
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	var circuit InnerCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	sizeSystem, lagrange := plonk.SRSSize(ccs)
	bAlpha := new(big.Int).SetInt64(rand.Int63())
	srs, err := kzg_bn254.NewSRS(uint64(sizeSystem), bAlpha)
	if err != nil {
		panic(err)
	}
	srsLagrange, err := kzg_bn254.NewSRS(uint64(sizeSystem), bAlpha)
	srsLagrange.Vk = srs.Vk
	srsLagrange.Pk.G1, _ = kzg_bn254.ToLagrangeG1(srs.Pk.G1[:lagrange])
	if err != nil {
		panic(err)
	}

	var w InnerCircuit
	w.X = 4
	w.Y = 4

	witness, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	witnessPub, err := witness.Public()
	if err != nil {
		panic(err)
	}
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		panic(err)
	}
	proof, err := plonk.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}
	err = plonk.Verify(proof, vk, witnessPub)
	if err != nil {
		panic(err)
	}
}
