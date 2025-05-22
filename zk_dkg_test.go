package zkdkg

import (
	"crypto/md5"
	crypto_rand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"

	"github.com/bane-labs/zk-dkg/mpc"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"

	"github.com/bane-labs/zk-dkg/circuit"
	"github.com/bane-labs/zk-dkg/helper"
	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark/backend"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

func TestBatchEncryptionWithMPC(t *testing.T) {
	assert := test.NewAssert(t)
	// To demo send N fragements to N nodes, N=batch
	var batch = 1
	// Generate node private key
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	// Compute public key
	f := randomPoly(5)
	t.Logf("Secret: [%s, %s, %s, %s, %s]", hex.EncodeToString(f.coeff[0].Bytes()), hex.EncodeToString(f.coeff[1].Bytes()), hex.EncodeToString(f.coeff[2].Bytes()), hex.EncodeToString(f.coeff[3].Bytes()), hex.EncodeToString(f.coeff[4].Bytes()))
	fis := make([]*fr_bls12381.Element, batch)
	pubKeys := make([]*ecies.PublicKey, batch)
	for i := 0; i < batch; i++ {
		key, err := ecies.GenerateKey(rand, crypto.S256(), nil)
		assert.NoError(err)
		pubKeys[i] = &key.PublicKey
		t.Logf("Encryption key: %s", hex.EncodeToString(crypto.FromECDSAPub(&key.ExportECDSA().PublicKey)))
		fi := new(fr_bls12381.Element).SetBigInt(f.evaluate(big.NewInt(int64(i + 1))))
		assert.NoError(err)
		fis[i] = fi
	}
	// Generate fragements and assigment and proof
	fisBytes, fisInts, bigFis, nonces, encryptedFis, rs, bigRs, err := circuit.PrepareEncryptedKeyShares(pubKeys, fis)
	assert.NoError(err)
	messages := encodeMessages(encryptedFis, bigRs, nonces)
	for i := 0; i < batch; i++ {
		t.Logf("Share message: %s", hex.EncodeToString(messages[i]))
	}
	// Read files
	innerCSSPath := "inner_ccs"
	innerPKPath := "inner_pk"
	innerVKPath := "inner_vk"
	innerCSS, err := helper.ReadCSS(innerCSSPath)
	assert.NoError(err)
	innerPK, err := helper.ReadGroth16ProvingKey(innerPKPath)
	assert.NoError(err)
	innerVK, err := helper.ReadGroth16VerifyingKey(innerVKPath)
	assert.NoError(err)
	innerCSSs := make([]constraint.ConstraintSystem, batch)
	innerPKs := make([]*groth16.ProvingKey, batch)
	innerVKs := make([]*groth16.VerifyingKey, batch)
	for i := 0; i < batch; i++ {
		innerCSSs[i] = innerCSS
		innerPKs[i] = innerPK
		innerVKs[i] = innerVK
	}
	outerCSSPath := "outer_ccs"
	outerPKPath := "outer_pk"
	outerVKPath := "outer_vk"
	outerCSS, err := helper.ReadCSS(outerCSSPath)
	assert.NoError(err)
	outerPK, err := helper.ReadPlonkProvingKey(outerPKPath)
	assert.NoError(err)
	outerVK, err := helper.ReadPlonkVerifyingKey(outerVKPath)
	assert.NoError(err)

	// Compute proof
	proof, witness, err := ProveMultipleKeyShareEncryption(outerCSS, outerPK, innerCSSs, innerPKs, innerVKs, pubKeys, rs, bigRs, fisBytes, fisInts, bigFis, encryptedFis, nonces)
	assert.NoError(err)

	// Verify proof
	publicWitness, err := witness.Public()
	assert.NoError(err)
	err = plonk.Verify(proof, outerVK, publicWitness, backend.WithVerifierHashToFieldFunction(sha256.New()))
	assert.NoError(err)
}

func TestTwoRecoverMessageGeneration(t *testing.T) {
	assert := test.NewAssert(t)
	// Generate node private key
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	// Compute public key
	fis := make([]*fr_bls12381.Element, 2)
	pubKeys := make([]*ecies.PublicKey, 2)
	for i := 0; i < 2; i++ {
		key, err := ecies.GenerateKey(rand, crypto.S256(), nil)
		assert.NoError(err)
		pubKeys[i] = &key.PublicKey
		t.Logf("Encryption key: %s", hex.EncodeToString(crypto.FromECDSAPub(&key.ExportECDSA().PublicKey)))
	}
	// Generate two secrets
	f1 := randomPoly(5)
	f2 := randomPoly(5)
	t.Logf("Secret 1: [%s, %s, %s, %s, %s]", hex.EncodeToString(f1.coeff[0].Bytes()), hex.EncodeToString(f1.coeff[1].Bytes()), hex.EncodeToString(f1.coeff[2].Bytes()), hex.EncodeToString(f1.coeff[3].Bytes()), hex.EncodeToString(f1.coeff[4].Bytes()))
	t.Logf("Secret 2: [%s, %s, %s, %s, %s]", hex.EncodeToString(f2.coeff[0].Bytes()), hex.EncodeToString(f2.coeff[1].Bytes()), hex.EncodeToString(f2.coeff[2].Bytes()), hex.EncodeToString(f2.coeff[3].Bytes()), hex.EncodeToString(f2.coeff[4].Bytes()))
	// Generate two shares with the same index
	fis[0] = new(fr_bls12381.Element).SetBigInt(f1.evaluate(big.NewInt(int64(1))))
	fis[1] = new(fr_bls12381.Element).SetBigInt(f2.evaluate(big.NewInt(int64(1))))

	// Generate fragements and assigment and proof
	fisBytes, fisInts, bigFis, nonces, encryptedFis, rs, bigRs, err := circuit.PrepareEncryptedKeyShares(pubKeys, fis)
	assert.NoError(err)
	messages := encodeMessages(encryptedFis, bigRs, nonces)
	for i := 0; i < 2; i++ {
		t.Logf("Share message: %s", hex.EncodeToString(messages[i]))
	}
	// Read files
	innerCSSPath := "inner_ccs"
	innerPKPath := "inner_pk"
	innerVKPath := "inner_vk"
	innerCSS, err := helper.ReadCSS(innerCSSPath)
	assert.NoError(err)
	innerPK, err := helper.ReadGroth16ProvingKey(innerPKPath)
	assert.NoError(err)
	innerVK, err := helper.ReadGroth16VerifyingKey(innerVKPath)
	assert.NoError(err)
	innerCSSs := make([]constraint.ConstraintSystem, 2)
	innerPKs := make([]*groth16.ProvingKey, 2)
	innerVKs := make([]*groth16.VerifyingKey, 2)
	for i := 0; i < 2; i++ {
		innerCSSs[i] = innerCSS
		innerPKs[i] = innerPK
		innerVKs[i] = innerVK
	}
	outerCSSPath := "outer_ccs"
	outerPKPath := "outer_pk"
	outerVKPath := "outer_vk"
	outerCSS, err := helper.ReadCSS(outerCSSPath)
	assert.NoError(err)
	outerPK, err := helper.ReadPlonkProvingKey(outerPKPath)
	assert.NoError(err)
	outerVK, err := helper.ReadPlonkVerifyingKey(outerVKPath)
	assert.NoError(err)

	// Compute proof
	proof, witness, err := ProveMultipleKeyShareEncryption(outerCSS, outerPK, innerCSSs, innerPKs, innerVKs, pubKeys, rs, bigRs, fisBytes, fisInts, bigFis, encryptedFis, nonces)
	assert.NoError(err)
	// Verify proof
	publicWitness, err := witness.Public()
	assert.NoError(err)
	err = plonk.Verify(proof, outerVK, publicWitness, backend.WithVerifierHashToFieldFunction(sha256.New()))
	assert.NoError(err)
	// Output proof data
	/*	proofData, cmts, cmtPok := helper.GetContractInput(proof)
		// proof.Ar, proof.Bs, proof.Krs
		t.Log("Proof:")
		for i := 0; i < 8; i++ {
			t.Log(proofData[i].String())
		}
		// commitments
		t.Log("Commitments:")
		for i := 0; i < len(cmts); i++ {
			t.Log(cmts[i].String())
		}
		// commitmentPok
		t.Log("CommitmentPok:")
		for i := 0; i < len(cmtPok); i++ {
			t.Log(cmtPok[i].String())
		}*/
}

func TestMPC(t *testing.T) {
	assert := test.NewAssert(t)
	prevPhase1 := t.TempDir() + "Phase1_1"
	curPhase1 := t.TempDir() + "Phase1_2"
	finalPhase1 := t.TempDir() + "Phase1_final"

	_, err := mpc.InitGroth16Phase1(prevPhase1, 262144)
	assert.NoError(err)
	mpc.ContributeGroth16Phase1(prevPhase1, curPhase1)
	mpc.SealGroth16Phase1(curPhase1, finalPhase1)

	var myCircuit = TempCircuit{
		Data:    make([]frontend.Variable, 10),
		SumHash: make([]frontend.Variable, 32),
	}
	css, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
	assert.NoError(err)

	srs, err := mpc.ReadGroth16SRSFromFile(finalPhase1)
	assert.NoError(err)

	prevPhase2 := t.TempDir() + "Phase2_1"
	curPhase2 := t.TempDir() + "Phase2_2"

	_, _, _, err = mpc.InitGroth16Phase2(css, finalPhase1, prevPhase2)
	assert.NoError(err)
	_, err = mpc.ContributeGroth16Phase2(prevPhase2, curPhase2)
	assert.NoError(err)

	var p2 mpcsetup.Phase2
	r1cs := css.(*cs.R1CS)
	evals := p2.Initialize(r1cs, srs)

	phase2, err := mpc.ReadGroth16Phase2FromFile(curPhase2)
	assert.NoError(err)
	p1, v1 := phase2.Seal(srs, &evals, []byte("beacon Phase 2"))
	pk := p1.(*groth16.ProvingKey)
	vk := v1.(*groth16.VerifyingKey)

	contractFilePath := "Verifier.sol"
	helper.ExportContract(vk, contractFilePath)

	data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	rawData := make([]frontend.Variable, len(data))
	for i := 0; i < len(data); i++ {
		rawData[i] = data[i]
	}
	sumHash := helper.GetHash(data)
	rawSumHash := make([]frontend.Variable, len(sumHash))
	for i := 0; i < len(sumHash); i++ {
		rawSumHash[i] = sumHash[i]
	}

	// Compute witness
	assignment := &TempCircuit{
		Data:    rawData,
		SumHash: rawSumHash,
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
	proof, err := groth16.Prove(css.(*cs.R1CS), pk, witness, backend.WithProverHashToFieldFunction(sha256.New()))
	assert.NoError(err)
	pubWitness, err := witness.Public()
	assert.NoError(err)
	err = groth16.Verify(proof, vk, pubWitness.Vector().(fr_bn254.Vector), backend.WithVerifierHashToFieldFunction(sha256.New()))
	assert.NoError(err)
}

type TempCircuit struct {
	Data    []frontend.Variable `gnark:",secret"`
	SumHash []frontend.Variable `gnark:",public"`
}

// Define declares the circuit's constraints
func (c *TempCircuit) Define(api frontend.API) error {
	DataBytes := make([]uints.U8, len(c.Data))
	for i := 0; i < len(DataBytes); i++ {
		DataBytes[i] = uints.U8{Val: c.Data[i]}
	}
	// hash function
	mc, _ := sha2.New(api)
	mc.Write(DataBytes)
	result := mc.Sum()
	// Check sum hash
	for i := 0; i < len(result); i++ {
		api.AssertIsEqual(result[i].Val, c.SumHash[i])
	}
	return nil
}

func randScalar() *big.Int {
	a, _ := crypto_rand.Int(crypto_rand.Reader, ecc.BLS12_381.ScalarField())
	return a
}

type Poly struct {
	coeff []*big.Int
}

func randomPoly(degree int) *Poly {
	coeff := make([]*big.Int, degree)

	for i := range coeff {
		fr := randScalar()
		coeff[i] = fr
	}
	return &Poly{
		coeff: coeff,
	}
}

func (p *Poly) evaluate(x *big.Int) *big.Int {
	i := len(p.coeff) - 1
	result := new(big.Int).Set(p.coeff[i])
	for i >= 0 {
		if i != len(p.coeff)-1 {
			result.Mul(result, x)
			result.Add(result, p.coeff[i])
		}
		i--
	}
	return result
}

func encodeMessages(encryptedFis [][]byte, bigRs []*secp256k1.G1Affine, nonces [][]byte) [][]byte {
	result := make([][]byte, 0)
	for i := range encryptedFis {
		bigRBytes := bigRs[i].RawBytes()
		prefix := append(bigRBytes[:], nonces[i]...)
		result = append(result, append(prefix, encryptedFis[i]...))
	}
	return result
}

func computeMd5(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	hash := md5.New()

	// Copy file to hasher
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	// Compute md5
	md5sum := hash.Sum(nil)
	// Print the result
	fmt.Printf("MD5 of the file: %x\n", md5sum)
	return nil
}
