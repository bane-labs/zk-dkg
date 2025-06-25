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
	"github.com/consensys/gnark-crypto/kzg"
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
	rootDir, err := helper.FindProjectRoot()
	assert.NoError(err)
	testDir := fmt.Sprintf("%s/%s/", rootDir, "circuit") // change the path, "cmd"(from mpccmd.go) or "circuit"(mock)
	maxBatchIDIndex := len(innerVKIDs) - 1               // max ccs's index
	testBatchIndex := 2                                  // index for test
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
		fisInts, bigFis, nonces, encryptedFis, rs, bigRs, err := PrepareEncryptedKeyShares(pubKeys, fis)
		assert.NoError(err)
		td[j] = Tempdata{data2: fisInts, data3: bigFis, data4: nonces, data5: encryptedFis, data6: rs, data7: bigRs, data8: pubKeys, data9: fis}
	}

	innerCCSs := make([]constraint.ConstraintSystem, len(innerVKIDs))
	innerPKs := make([]plonk.ProvingKey, len(innerVKIDs))
	innerVKs := make([]plonk.VerifyingKey, len(innerVKIDs))
	srscFlag := false
	var srsc kzg_bn254.SRS
	// if pk/vk pairs has been generated, we don't need to load or generate srs/srsc
	checkSRSC := func() {
		srscPath := testDir + "srs_2_canonical" // not kzg.mpcsetup, is kzg.srs(canonical), points on curve
		if !srscFlag {
			// if srsc has not been generated
			if _, err := os.Stat(srscPath); err != nil {
				circuit := GetBatchEncryptionCircuit(td[maxBatchIDIndex].data5)
				ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
				require.NoError(t, err)
				srsMpcSsetupPath := testDir + "srs_2"
				if _, err = os.Stat(srsMpcSsetupPath); err != nil {
					// if mpcsetup is not generated
					err = mockSRCMPC("srs_", ccs, 2)
					if err != nil {
						require.NoError(t, err)
					}
				} else {
					// load mpcsetup
					file, err := os.Open(srsMpcSsetupPath)
					require.NoError(t, err)
					var srs kzg_bn254.MpcSetup
					_, err = srs.ReadFrom(file)
					require.NoError(t, err)
					err = file.Close()
					require.NoError(t, err)
					err = SealSRSMpcSetup(srs, srscPath)
					require.NoError(t, err)
				}
			}
			srscFlag = true
			file, err := os.Open(srscPath)
			require.NoError(t, err)
			_, err = srsc.ReadFrom(file)
			require.NoError(t, err)
			err = file.Close()
			require.NoError(t, err)
		}
	}

	for j := 0; j < len(innerVKIDs); j++ {
		innerCCSPath := testDir + "inner_ccs_" + strconv.Itoa(innerVKIDs[j])
		innerPKPath := testDir + "inner_pk_" + strconv.Itoa(innerVKIDs[j])
		innerVKPath := testDir + "inner_vk_" + strconv.Itoa(innerVKIDs[j])
		if _, err := os.Stat(innerCCSPath); err != nil {
			circuit := GetBatchEncryptionCircuit(td[j].data5)
			ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
			require.NoError(t, err)
			// check srs has been generated
			checkSRSC()
			// here we just input srsc, not need to seal in each loop(too slow, and cpu usage is very low)
			_, _, err = mockSeal("inner_", ccs, &srsc, innerVKIDs[j])
			if err != nil {
				require.NoError(t, err)
			}
		}

		innerCCS, err := helper.ReadCCS(innerCCSPath)
		require.NoError(t, err)
		innerPK, err := helper.ReadPlonkProvingKey(innerPKPath, ecc.BN254)
		require.NoError(t, err)
		innerVK, err := helper.ReadPlonkVerifyingKey(innerVKPath, ecc.BN254)
		require.NoError(t, err)
		innerCCSs[j] = innerCCS
		innerPKs[j] = innerPK
		innerVKs[j] = innerVK
	}
	nbPublic, nbCommitment := innerCCSs[0].GetNbPublicVariables(), len(innerCCSs[0].GetCommitments().CommitmentIndexes())
	for i := 0; i < len(innerCCSs); i++ {
		if innerCCSs[i].GetNbPublicVariables() != nbPublic || len(innerCCSs[i].GetCommitments().CommitmentIndexes()) != nbCommitment {
			t.Fatal(fmt.Errorf("all inner ccs should have the same len(public) and len(commitments)"))
		}
	}
	outerCircuit, err := GetRecursionEncryptionCircuit(nbPublic, nbCommitment, innerVKs)
	require.NoError(t, err)
	innerAssignments, sumHash := ComputeMultipleKeyShareEncryptionAssignment(innerVKIDs[testBatchIndex], td[testBatchIndex].data8, td[testBatchIndex].data6, td[testBatchIndex].data7, td[testBatchIndex].data2, td[testBatchIndex].data3, td[testBatchIndex].data5, td[testBatchIndex].data4)
	rawSumHash := make([]frontend.Variable, len(sumHash))
	for i := 0; i < len(sumHash); i++ {
		rawSumHash[i] = sumHash[i]
	}
	outerAssignment, err := ComputeRecursionEncryptionAssignment(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), testBatchIndex, innerVKs, innerCCSs[testBatchIndex], innerPKs[testBatchIndex], innerVKs[testBatchIndex], innerAssignments, rawSumHash)
	require.NoError(t, err)
	/*	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BN254.ScalarField())
		if err != nil {
			panic(err)
		}*/
	outerCCSPath := testDir + "outer_ccs"
	outerPKPath := testDir + "outer_pk"
	outerVKPath := testDir + "outer_vk"
	//outerContract := "outer_contract.sol"
	if _, err := os.Stat(outerCCSPath); err != nil {
		mockOuterCcs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, outerCircuit)
		require.NoError(t, err)
		checkSRSC()
		_, _, err = mockSeal("outer_", mockOuterCcs, &srsc) // similarly, just input srsc
		require.NoError(t, err)
	}
	outerCCS, err := helper.ReadCCS(outerCCSPath)
	require.NoError(t, err)
	fmt.Println(outerCCS.GetNbConstraints())
	outerPK, err := helper.ReadPlonkProvingKey(outerPKPath, ecc.BN254)
	require.NoError(t, err)
	outerVK, err := helper.ReadPlonkVerifyingKey(outerVKPath, ecc.BN254)
	require.NoError(t, err)

	witness, err := frontend.NewWitness(outerAssignment, ecc.BN254.ScalarField())
	require.NoError(t, err)
	witnessPub, err := witness.Public()
	require.NoError(t, err)
	proof, err := plonk.Prove(outerCCS, outerPK, witness)
	require.NoError(t, err)
	err = plonk.Verify(proof, outerVK, witnessPub)
	require.NoError(t, err)
	//helper.ExportContract(outerVKs, outerContract)
	output := helper.GetContractInput(proof)
	publicInputs := []uint32{uint32(testBatchIndex)}
	for k := 0; k < len(sumHash); k++ {
		publicInputs = append(publicInputs, uint32(sumHash[k]))
	}
	fmt.Println("Plonk proof is: \n", "0x"+hex.EncodeToString(output))
	fmt.Println("Onchain Public input is: \n", publicInputs)

}

type Tempdata struct {
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
	path := prefix + strconv.Itoa(nContributions) + "_canonical"
	// here we get p (mpcsetup)
	// since srsc = p.Seal() is too slow and can be reused
	// so we export srsc
	return SealSRSMpcSetup(p, path)

}

func SealSRSMpcSetup(p kzg_bn254.MpcSetup, path string) error {
	srsc := p.Seal([]byte("beacon SRS")) // in gnark, this challenge is fixed (in verifier, e.g. plonk.Verify)
	f, err := os.Create(path)
	defer f.Close()
	if err != nil {
		return err
	}
	_, err = srsc.WriteTo(f)
	if err != nil {
		return err
	}
	// we export srsc (canonical), since the srsl(lagrange) cannot be reused, srsl = toLagrange(srsc[:lagrange]) should be performed in each circuit
	return nil
}

func mockSeal(prefix string, ccs constraint.ConstraintSystem, srs kzg.SRS, innerVKID ...int) (pk plonk.ProvingKey, vk plonk.VerifyingKey, err error) {
	suffix := ""
	if len(innerVKID) != 0 {
		suffix = fmt.Sprintf("_%d", innerVKID[0])
	}
	scs := ccs.(*cs.SparseR1CS)
	_, lagrange := plonk.SRSSize(scs)
	srsLagrange := &kzg_bn254.SRS{Vk: srs.(*kzg_bn254.SRS).Vk}
	srsLagrange.Pk.G1, err = kzg_bn254.ToLagrangeG1(srs.(*kzg_bn254.SRS).Pk.G1[:lagrange])
	if err != nil {
		return nil, nil, err
	}
	p1, v1, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		return nil, nil, err
	}
	pk = p1.(*plonk_bn254.ProvingKey)
	vk = v1.(*plonk_bn254.VerifyingKey)
	err = helper.ExportPlonkProvingKey(pk, prefix+"pk"+suffix)
	if err != nil {
		return nil, nil, err
	}
	err = helper.ExportPlonkVerifyingKey(vk, prefix+"vk"+suffix)
	if err != nil {
		return nil, nil, err
	}
	err = helper.ExportCCS(ccs, prefix+"ccs"+suffix)
	if err != nil {
		return nil, nil, err
	}
	return pk, vk, nil
}
