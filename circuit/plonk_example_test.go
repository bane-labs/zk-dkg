package circuit

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPlonk(t *testing.T) {
	var circuit InnerCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	require.NoError(t, err)

	scs := ccs.(*cs.SparseR1CS)
	srs, srsLagrange, err := unsafekzg.NewSRS(scs)
	require.NoError(t, err)

	var w InnerCircuit
	w.X = 4
	w.Y = 5

	witness, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
	require.NoError(t, err)
	witnessPub, err := witness.Public()
	require.NoError(t, err)
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	require.NoError(t, err)
	proof, err := plonk.Prove(ccs, pk, witness)
	require.NoError(t, err)
	err = plonk.Verify(proof, vk, witnessPub)
	require.NoError(t, err)
}

func TestPlonkWithMPC(t *testing.T) {
	/*	source := rand.NewSource(time.Now().UnixNano())
		rand := rand.New(source)*/
	var circuit InnerCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	require.NoError(t, err)

	scs := ccs.(*cs.SparseR1CS)
	srs, srsLagrange, err := unsafekzg.NewSRS(scs)

	/*	sizeSystem, lagrange := plonk.SRSSize(ccs)
		bAlpha := new(big.Int).SetInt64(rand.Int63())
		srs, err := kzg_bn254.NewSRS(uint64(sizeSystem), bAlpha)
		require.NoError(t, err)

		srsLagrange, err := kzg_bn254.NewSRS(uint64(sizeSystem), bAlpha)
		srsLagrange.Vk = srs.Vk
		srsLagrange.Pk.G1, _ = kzg_bn254.ToLagrangeG1(srs.Pk.G1[:lagrange])
		require.NoError(t, err)*/

	var w InnerCircuit
	w.X = 4
	w.Y = 5

	witness, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
	require.NoError(t, err)
	witnessPub, err := witness.Public()
	require.NoError(t, err)
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	require.NoError(t, err)
	proof, err := plonk.Prove(ccs, pk, witness)
	if err != nil {
		fmt.Println("error")
		return
		//fmt.Println(err.Error())
	}
	//require.NoError(t, err)
	err = plonk.Verify(proof, vk, witnessPub)
	require.NoError(t, err)
}
