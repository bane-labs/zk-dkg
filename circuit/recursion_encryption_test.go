package circuit

import (
	"encoding/hex"
	"fmt"
	"math"
	"math/rand"
	"os"
	"strconv"
	"testing"
	"time"

	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/stretchr/testify/require"

	"github.com/bane-labs/zk-dkg/helper"
	"github.com/bane-labs/zk-dkg/mpc"
	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

func TestRecursionEncryptionCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	// To demo send N fragements to N nodes, N=batch
	var batch = 1
	// Generate node private key
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	// Computing public key
	fis := make([]fr_bls12381.Element, batch)
	pubKeys := make([]*ecies.PublicKey, batch)
	for i := 0; i < batch; i++ {
		key, err := ecies.GenerateKey(rand, crypto.S256(), nil)
		assert.NoError(err)
		pubKeys[i] = &key.PublicKey
		var fi fr_bls12381.Element
		fi.SetRandom()
		fis[i] = fi
	}
	// Generate fragements and assigment
	fisBytes, fisInts, bigFis, nonces, encryptedFis, rs, bigRs := PrepareEncryptedKeyShares(pubKeys, fis)

	innerCssPath := "inner_ccs"
	innerPkPath := "inner_pk"
	innerVkPath := "inner_vk"
	if _, err := os.Stat(innerCssPath); err != nil {
		mockinnerCircuit := ComputeSingleKeyShareEncryptionCircuit(fisBytes[0], encryptedFis[0])
		mockinnerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, mockinnerCircuit)
		require.NoError(t, err)
		_, _, err = mockInnerCircuitMPC("inner_", mockinnerCcs, 2, 2, uint64(math.Pow(2, 21)))
		require.NoError(t, err)
	}

	innerCcss, innerPKs, innerVKs := ComputeMultipleKeyShareEncryptionCircuitByFile(batch, innerCssPath, innerPkPath, innerVkPath)
	innerAssignments, sumHash := ComputeMultipleKeyShareEncryptionAssignment(batch, pubKeys, rs, bigRs, fisBytes, fisInts, bigFis, encryptedFis, nonces)
	rawSumHash := make([]frontend.Variable, len(sumHash))
	for i := 0; i < len(sumHash); i++ {
		rawSumHash[i] = sumHash[i]
	}
	outerCircuit := ComputeRecursionEncryptionCircuit(batch, innerCcss, innerVKs)
	outerAssignment := ComputeRecursionEncryptionAssignment(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), batch, innerCcss, innerPKs, innerVKs, innerAssignments, rawSumHash)
	/*	err := test.IsSolved(outerCircuit, outerAssignment, ecc.BN254.ScalarField())
		if err != nil {
			panic(err)
		}*/
	outerCssPath := "outer_ccs"
	outerPkPath := "outer_pk"
	outerVkPath := "outer_vk"
	//outerContract := "outer_contract.sol"
	if _, err := os.Stat(outerCssPath); err != nil {
		mockouterCcs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, outerCircuit)
		require.NoError(t, err)
		_, _, err = mockSRCMPC("outer_", mockouterCcs, 2)
		require.NoError(t, err)
	}

	outerCcss, outerPKs, outerVKs := ComputeRecursionEncryptionCircuitByFile(outerCssPath, outerPkPath, outerVkPath)

	witness, err := frontend.NewWitness(outerAssignment, ecc.BN254.ScalarField())
	require.NoError(t, err)
	witnessPub, err := witness.Public()
	require.NoError(t, err)
	proof, err := plonk.Prove(outerCcss, outerPKs, witness)
	require.NoError(t, err)
	err = plonk.Verify(proof, outerVKs, witnessPub)
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

func mockInnerCircuitMPC(folderPath string, ccs constraint.ConstraintSystem, nContributionsPhase1 int, nContributionsPhase2 int, power uint64) (*groth16.ProvingKey, *groth16.VerifyingKey, error) {
	_, err := mpc.InitInnerPhase1(folderPath+"Phase1_1", power)
	if err != nil {
		return nil, nil, err
	}
	// All members build and verify contributions for phase1
	for i := 1; i < nContributionsPhase1; i++ {
		prepath := folderPath + "Phase1_" + strconv.Itoa(i)
		nextPath := folderPath + "Phase1_" + strconv.Itoa(i+1)
		_, err = mpc.ContributeInnerPhase1(prepath, nextPath)
		if err != nil {
			return nil, nil, err
		}
	}
	mpc.InnerSeal(folderPath+"Phase1_"+strconv.Itoa(nContributionsPhase1), folderPath+"Phase1_final")

	evals, srs, _, err := mpc.InitInnerPhase2(ccs, folderPath+"Phase1_final", folderPath+"Phase2_1")
	if err != nil {
		return nil, nil, err
	}
	// All members build and verify contributions for phase2
	for i := 1; i < nContributionsPhase2; i++ {
		prepath := folderPath + "Phase2_" + strconv.Itoa(i)
		nextPath := folderPath + "Phase2_" + strconv.Itoa(i+1)
		_, err = mpc.ContributeInnerPhase2(prepath, nextPath)
		if err != nil {
			return nil, nil, err
		}
	}
	phase2, err := mpc.ReadInnerPhase2FromFile(folderPath + "Phase2_" + strconv.Itoa(nContributionsPhase1))
	if err != nil {
		return nil, nil, err
	}
	// Extract the proving and verifying keys
	p1, v1 := phase2.Seal(&srs, &evals, []byte("beacon Phase 2"))
	pk := p1.(*groth16.ProvingKey)
	vk := v1.(*groth16.VerifyingKey)
	helper.ExportInnerProvingKey(pk, folderPath+"pk")
	helper.ExportInnerVerifyingKey(vk, folderPath+"vk")
	helper.ExportCSS(ccs, folderPath+"ccs")
	return pk, vk, err
}

func mockSRCMPC(folderPath string, ccs constraint.ConstraintSystem, nContributions int) (pk plonk.ProvingKey, vk plonk.VerifyingKey, err error) {
	scs := ccs.(*cs.SparseR1CS)
	srsSize, lagrange := plonk.SRSSize(scs)

	p := kzg_bn254.InitializeSetup(srsSize)
	for i := 0; i < nContributions; i++ {
		if i > 0 {
			in, err := os.Open(folderPath + strconv.Itoa(i))
			if err != nil {
				return nil, nil, err
			}
			_, err = p.ReadFrom(in)
			if err != nil {
				return nil, nil, err
			}
			err = in.Close()
			if err != nil {
				return nil, nil, err
			}
		}
		p.Contribute()
		out, err := os.Create(folderPath + strconv.Itoa(i+1))
		if err != nil {
			return nil, nil, err
		}
		_, err = p.WriteTo(out)
		if err != nil {
			return nil, nil, err
		}
		err = out.Close()
		if err != nil {
			return nil, nil, err
		}
	}
	srs := p.Seal([]byte("test"))

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
	helper.ExportOuterProvingKey(pk, folderPath+"pk")
	helper.ExportOuterVerifyingKey(vk, folderPath+"vk")
	helper.ExportCSS(ccs, folderPath+"ccs")
	return pk, vk, nil
}
