package circuit

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/bane-labs/zk-dkg/helper"
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/stretchr/testify/require"
)

func TestRecursionEncryptionCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	innerVKIDs := []int{1, 2, 7}
	MaxBatchIDIndex := len(innerVKIDs) - 1
	td := make([]Tempdata, len(innerVKIDs))
	for j := 0; j < len(innerVKIDs); j++ {
		batch := innerVKIDs[j]
		source := rand.NewSource(time.Now().UnixNano())
		rand := rand.New(source)
		// Computing public key
		fis := make([]*fr_bls12381.Element, batch)
		pubKeys := make([]*ecies.PublicKey, batch)
		for i := 0; i < batch; i++ {
			key, err := ecies.GenerateKey(rand, crypto.S256(), nil)
			assert.NoError(err)
			pubKeys[i] = &key.PublicKey
			fi := new(fr_bls12381.Element)
			_, err = fi.SetRandom()
			assert.NoError(err)
			fis[i] = fi
		}
		// Generate fragements and assigment
		fisBytes, fisInts, bigFis, nonces, encryptedFis, rs, bigRs, err := PrepareEncryptedKeyShares(pubKeys, fis)
		assert.NoError(err)
		td[j] = Tempdata{data1: fisBytes, data2: fisInts, data3: bigFis, data4: nonces, data5: encryptedFis, data6: rs, data7: bigRs, data8: pubKeys, data9: fis}
	}

	innerCSSs := make([]constraint.ConstraintSystem, len(innerVKIDs))
	innerPKs := make([]plonk.ProvingKey, len(innerVKIDs))
	innerVKs := make([]plonk.VerifyingKey, len(innerVKIDs))
	srsPath := "srs_2"
	if _, err := os.Stat(srsPath); err != nil {
		circuit := GetBatchEncryptionCircuit(td[MaxBatchIDIndex].data1, td[MaxBatchIDIndex].data5)
		css, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
		require.NoError(t, err)
		err = mockSRCMPC("srs_", css, 2)
		if err != nil {
			require.NoError(t, err)
		}
	}

	for j := 0; j < len(innerVKIDs); j++ {
		innerCSSPath := "inner_ccs_" + strconv.Itoa(innerVKIDs[j])
		innerPKPath := "inner_pk_" + strconv.Itoa(innerVKIDs[j])
		innerVKPath := "inner_vk_" + strconv.Itoa(innerVKIDs[j])
		if _, err := os.Stat(innerCSSPath); err != nil {
			circuit := GetBatchEncryptionCircuit(td[j].data1, td[j].data5)
			css, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
			require.NoError(t, err)
			_, _, err = mockSeal("inner_", css, srsPath, innerVKIDs[j])
			if err != nil {
				require.NoError(t, err)
			}
		}

		innerCSS, err := helper.ReadCSS(innerCSSPath)
		require.NoError(t, err)
		innerPK, err := helper.ReadPlonkProvingKey(innerPKPath, ecc.BN254)
		require.NoError(t, err)
		innerVK, err := helper.ReadPlonkVerifyingKey(innerVKPath, ecc.BN254)
		require.NoError(t, err)
		innerCSSs[j] = innerCSS
		innerPKs[j] = innerPK
		innerVKs[j] = innerVK
	}
	outerCircuit, err := GetRecursionEncryptionCircuit(innerCSSs[0], innerVKs, innerVKIDs)
	require.NoError(t, err)
	innerAssignments, sumHash := ComputeMultipleKeyShareEncryptionAssignment(innerVKIDs[MaxBatchIDIndex], td[MaxBatchIDIndex].data8, td[MaxBatchIDIndex].data6, td[MaxBatchIDIndex].data7, td[MaxBatchIDIndex].data1, td[MaxBatchIDIndex].data2, td[MaxBatchIDIndex].data3, td[MaxBatchIDIndex].data5, td[MaxBatchIDIndex].data4)
	rawSumHash := make([]frontend.Variable, len(sumHash))
	for i := 0; i < len(sumHash); i++ {
		rawSumHash[i] = sumHash[i]
	}
	outerAssignment, err := ComputeRecursionEncryptionAssignment(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), innerVKIDs[MaxBatchIDIndex], innerCSSs[MaxBatchIDIndex], innerPKs[MaxBatchIDIndex], innerVKs[MaxBatchIDIndex], innerAssignments, rawSumHash)
	require.NoError(t, err)
	/*	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BN254.ScalarField())
		if err != nil {
			panic(err)
		}*/
	outerCSSPath := "outer_ccs"
	outerPKPath := "outer_pk"
	outerVKPath := "outer_vk"
	//outerContract := "outer_contract.sol"
	if _, err := os.Stat(outerCSSPath); err != nil {
		mockOuterCcs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, outerCircuit)
		require.NoError(t, err)
		_, _, err = mockOuterSeal("outer_", mockOuterCcs, srsPath)
		require.NoError(t, err)
	}
	outerCSS, err := helper.ReadCSS(outerCSSPath)
	require.NoError(t, err)
	outerPK, err := helper.ReadPlonkProvingKey(outerPKPath, ecc.BN254)
	require.NoError(t, err)
	outerVK, err := helper.ReadPlonkVerifyingKey(outerVKPath, ecc.BN254)
	require.NoError(t, err)

	witness, err := frontend.NewWitness(outerAssignment, ecc.BN254.ScalarField())
	require.NoError(t, err)
	witnessPub, err := witness.Public()
	require.NoError(t, err)
	proof, err := plonk.Prove(outerCSS, outerPK, witness)
	require.NoError(t, err)
	err = plonk.Verify(proof, outerVK, witnessPub)
	require.NoError(t, err)
	//helper.ExportContract(outerVKs, outerContract)
	output := helper.GetContractInput(proof)
	var temp = ""
	for k := 0; k < len(sumHash); k++ {
		temp = temp + "\"" + strconv.Itoa(int(sumHash[k])) + "\"" + ","
	}
	fmt.Println("public input is", temp)
	fmt.Println("Plonk proof is", "0x"+hex.EncodeToString(output))
}

type Tempdata struct {
	data1 [][]byte
	data2 []*big.Int
	data3 []*bls12381.G1Affine
	data4 [][]byte
	data5 [][]byte
	data6 []*big.Int
	data7 []*secp256k1.G1Affine
	data8 []*ecies.PublicKey
	data9 []*fr_bls12381.Element
}

func mockSRCMPC(prefix string, ccs constraint.ConstraintSystem, nContributions int) error {
	scs := ccs.(*cs.SparseR1CS)
	srsSize, _ := plonk.SRSSize(scs)

	p := kzg_bn254.InitializeSetup(srsSize)
	for i := 0; i < nContributions; i++ {
		if i > 0 {
			in, err := os.Open(prefix + strconv.Itoa(i))
			if err != nil {
				return err
			}
			_, err = p.ReadFrom(in)
			if err != nil {
				return err
			}
			err = in.Close()
			if err != nil {
				return err
			}
		}
		p.Contribute()
		out, err := os.Create(prefix + strconv.Itoa(i+1))
		if err != nil {
			return err
		}
		_, err = p.WriteTo(out)
		if err != nil {
			return err
		}
		err = out.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func mockSeal(prefix string, ccs constraint.ConstraintSystem, srsPath string, innerVKID int) (pk plonk.ProvingKey, vk plonk.VerifyingKey, err error) {
	scs := ccs.(*cs.SparseR1CS)
	srsSize, lagrange := plonk.SRSSize(scs)
	p := kzg_bn254.InitializeSetup(srsSize)
	file, err := os.Open(srsPath)
	_, err = p.ReadFrom(file)
	if err != nil {
		return nil, nil, err
	}
	srs := p.Seal([]byte("beacon SRS"))
	srsLagrange := &kzg_bn254.SRS{Vk: srs.Vk}
	srsLagrange.Pk.G1, err = kzg_bn254.ToLagrangeG1(srs.Pk.G1[:lagrange])
	if err != nil {
		return nil, nil, err
	}
	p1, v1, err := plonk.Setup(ccs, &srs, srsLagrange)
	if err != nil {
		return nil, nil, err
	}
	pk = p1.(*plonk_bn254.ProvingKey)
	vk = v1.(*plonk_bn254.VerifyingKey)
	err = helper.ExportPlonkProvingKey(pk, prefix+"pk_"+strconv.Itoa(innerVKID))
	if err != nil {
		return nil, nil, err
	}
	err = helper.ExportPlonkVerifyingKey(vk, prefix+"vk_"+strconv.Itoa(innerVKID))
	if err != nil {
		return nil, nil, err
	}
	err = helper.ExportCSS(ccs, prefix+"ccs_"+strconv.Itoa(innerVKID))
	if err != nil {
		return nil, nil, err
	}
	return pk, vk, nil
}

func mockOuterSeal(prefix string, ccs constraint.ConstraintSystem, srsPath string) (pk plonk.ProvingKey, vk plonk.VerifyingKey, err error) {
	scs := ccs.(*cs.SparseR1CS)
	srsSize, lagrange := plonk.SRSSize(scs)
	p := kzg_bn254.InitializeSetup(srsSize)
	file, err := os.Open(srsPath)
	_, err = p.ReadFrom(file)
	if err != nil {
		return nil, nil, err
	}
	srs := p.Seal([]byte("beacon SRS"))
	srsLagrange := &kzg_bn254.SRS{Vk: srs.Vk}
	srsLagrange.Pk.G1, err = kzg_bn254.ToLagrangeG1(srs.Pk.G1[:lagrange])
	if err != nil {
		return nil, nil, err
	}
	p1, v1, err := plonk.Setup(ccs, &srs, srsLagrange)
	if err != nil {
		return nil, nil, err
	}
	pk = p1.(*plonk_bn254.ProvingKey)
	vk = v1.(*plonk_bn254.VerifyingKey)
	err = helper.ExportPlonkProvingKey(pk, prefix+"pk")
	if err != nil {
		return nil, nil, err
	}
	err = helper.ExportPlonkVerifyingKey(vk, prefix+"vk")
	if err != nil {
		return nil, nil, err
	}
	err = helper.ExportCSS(ccs, prefix+"ccs")
	if err != nil {
		return nil, nil, err
	}
	return pk, vk, nil
}
