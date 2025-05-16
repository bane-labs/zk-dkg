package circuit

import (
	"math"
	"math/rand"
	"os"
	"strconv"
	"testing"
	"time"

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
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/stretchr/testify/require"
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

	cssPath := "test_ccs"
	pkPath := "test_pk"
	vkPath := "test_vk"
	if _, err := os.Stat(cssPath); err != nil {
		mockCircuit := ComputeSingleKeyShareEncryptionCircuit(fisBytes[0], encryptedFis[0])
		mockinnerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, mockCircuit)
		if err != nil {
			panic(err)
		}
		_, _, err = mockInnerCircuitMPC("", mockinnerCcs, 2, 2, uint64(math.Pow(2, 21)))
		if err != nil {
			panic(err)
		}
	}

	innerCcss, innerPKs, innerVKs := ComputeMultipleKeyShareEncryptionCircuitByFile(batch, cssPath, pkPath, vkPath)
	commentsHash := ComputeCommHash(batch, pubKeys, rs, bigRs, fisBytes, bigFis, encryptedFis, nonces)
	innerAssignments := ComputeMultipleKeyShareEncryptionAssignment(batch, pubKeys, rs, bigRs, fisBytes, fisInts, bigFis, encryptedFis, nonces)
	outerCircuit := ComputeRecursionEncryptionCircuit(batch, innerCcss, innerVKs)
	outerAssignment := ComputeRecursionEncryptionAssignment(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), batch, innerCcss, innerPKs, innerVKs, innerAssignments, commentsHash)
	/*	err := test.IsSolved(outerCircuit, outerAssignment, ecc.BN254.ScalarField())
		if err != nil {
			panic(err)
		}*/
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, outerCircuit)
	require.NoError(t, err)
	scs := ccs.(*cs.SparseR1CS)

	sizeSystem, lagrange := plonk.SRSSize(scs)

	srs, err := mockSRCMPC("PlonkMPC", 2, sizeSystem)
	if err != nil {
		panic(err)
	}
	srsLagrange := &kzg_bn254.SRS{Vk: srs.Vk}
	srsLagrange.Pk.G1, err = kzg_bn254.ToLagrangeG1(srs.Pk.G1[:lagrange])
	if err != nil {
		panic(err)
	}
	witness, err := frontend.NewWitness(outerAssignment, ecc.BN254.ScalarField())
	require.NoError(t, err)
	witnessPub, err := witness.Public()
	require.NoError(t, err)
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	require.NoError(t, err)
	proof, err := plonk.Prove(ccs, pk, witness)
	require.NoError(t, err)
	err = plonk.Verify(proof, vk, witnessPub)
	require.NoError(t, err)
	/*	p := proof.(*plonk_bn254.Proof)
		serializedProof := p.MarshalSolidity()*/
	/*	f, err := os.Create("contract_plonk.sol")
			require.NoError(t, err)
			err = vk.ExportSolidity(f)
			require.NoError(t, err)

	}*/
}

func mockInnerCircuitMPC(folderPath string, ccs constraint.ConstraintSystem, nContributionsPhase1 int, nContributionsPhase2 int, power uint64) (*groth16.ProvingKey, *groth16.VerifyingKey, error) {
	_, err := mpc.InitPhase1(folderPath+"Phase1_1", power)
	if err != nil {
		return nil, nil, err
	}
	// All members build and verify contributions for phase1
	for i := 1; i < nContributionsPhase1; i++ {
		prepath := folderPath + "Phase1_" + strconv.Itoa(i)
		nextPath := folderPath + "Phase1_" + strconv.Itoa(i+1)
		_, err = mpc.ContributePhase1(prepath, nextPath)
		if err != nil {
			return nil, nil, err
		}
	}
	mpc.Seal(folderPath+"Phase1_"+strconv.Itoa(nContributionsPhase1), folderPath+"Phase1_final")

	evals, srs, _, err := mpc.InitPhase2(ccs, folderPath+"Phase1_final", folderPath+"Phase2_1")
	if err != nil {
		return nil, nil, err
	}
	// All members build and verify contributions for phase2
	for i := 1; i < nContributionsPhase2; i++ {
		prepath := folderPath + "Phase2_" + strconv.Itoa(i)
		nextPath := folderPath + "Phase2_" + strconv.Itoa(i+1)
		_, err = mpc.ContributePhase2(prepath, nextPath)
		if err != nil {
			return nil, nil, err
		}
	}
	phase2, err := mpc.ReadPhase2FromFile(folderPath + "Phase2_" + strconv.Itoa(nContributionsPhase1))
	if err != nil {
		return nil, nil, err
	}
	// Extract the proving and verifying keys
	p1, v1 := phase2.Seal(&srs, &evals, []byte("beacon Phase 2"))
	pk := p1.(*groth16.ProvingKey)
	vk := v1.(*groth16.VerifyingKey)
	helper.ExportProvingKey(pk, folderPath+"test_pk")
	helper.ExportVerifyingKey(vk, folderPath+"test_vk")
	helper.ExportCSS(ccs, folderPath+"test_ccs")
	return pk, vk, err
}

func mockSRCMPC(folderPath string, nContributions int, srsSize int) (*kzg_bn254.SRS, error) {
	p := kzg_bn254.InitializeSetup(srsSize)
	for i := range nContributions {
		if i > 0 {
			in, err := os.Open(folderPath + strconv.Itoa(i))
			if err != nil {
				return nil, err
			}
			_, err = p.ReadFrom(in)
			if err != nil {
				return nil, err
			}
			err = in.Close()
			if err != nil {
				return nil, err
			}
		}
		p.Contribute()
		out, err := os.Create(folderPath + strconv.Itoa(i+1))
		if err != nil {
			return nil, err
		}
		_, err = p.WriteTo(out)
		if err != nil {
			return nil, err
		}
		err = out.Close()
		if err != nil {
			return nil, err
		}
	}
	res := p.Seal([]byte("test"))
	return &res, nil
}
