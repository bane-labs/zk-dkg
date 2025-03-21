package zkdkg

import (
	"crypto/md5"
	crypto_rand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/bane-labs/zk-dkg/mpc"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/stretchr/testify/assert"
	"io"
	"math/big"
	"math/rand"
	"os"
	"strconv"
	"testing"
	"time"

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
	var batch = 7
	// Generate node private key
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	// Compute public key
	f := randomPoly(5)
	t.Logf("Secret: [%s, %s, %s, %s, %s]", hex.EncodeToString(f.coeff[0].Bytes()), hex.EncodeToString(f.coeff[1].Bytes()), hex.EncodeToString(f.coeff[2].Bytes()), hex.EncodeToString(f.coeff[3].Bytes()), hex.EncodeToString(f.coeff[4].Bytes()))
	fis := make([]fr_bls12381.Element, batch)
	pubKeys := make([]*ecies.PublicKey, batch)
	for i := 0; i < batch; i++ {
		key, err := ecies.GenerateKey(rand, crypto.S256(), nil)
		assert.NoError(err)
		pubKeys[i] = &key.PublicKey
		t.Logf("Encryption key: %s", hex.EncodeToString(crypto.FromECDSAPub(&key.ExportECDSA().PublicKey)))
		var fi fr_bls12381.Element
		fi.SetBigInt(f.evaluate(big.NewInt(int64(i + 1))))
		fis[i] = fi
		t.Logf("Secret share: %v", hex.EncodeToString(f.evaluate(big.NewInt(int64(i+1))).Bytes()))
	}
	// Generate fragements and assigment and proof
	fisBytes, fisInts, bigFis, nonces, encryptedFis, rs, bigRs := circuit.PrepareEncryptedKeyShares(pubKeys, fis)
	messages := encodeMessages(encryptedFis, bigRs, nonces)
	for i := 0; i < batch; i++ {
		t.Logf("Share message: %s", hex.EncodeToString(messages[i]))
	}
	// There are two ways to compute a proof
	// 1) From an existing MPC file
	phase1Path := "Phase1_" + strconv.Itoa(3)
	phase2Path := "Phase2_" + strconv.Itoa(3)
	vk, proof, witness, err := ProveMultipleKeyShareEncryption(phase1Path, phase2Path, pubKeys, rs, bigRs, fisBytes, fisInts, bigFis, encryptedFis, nonces)
	assert.NoError(err)
	// 2) From a new MPC file
	/*	css, _, assignment, err := circuit.BatchComputingAssignment(batch, pubKeys, rs, rb, fiBytes, sfi, bfi, ctt, nonce)
		assert.NoError(err)
		_, vk, proof, witness, err := computingProof2(css, assignment)
		assert.NoError(err)*/
	publicWitness, err := witness.Public()
	assert.NoError(err)
	// Verify proof
	err = groth16.Verify(proof, &vk, publicWitness.Vector().(fr_bn254.Vector), backend.WithVerifierHashToFieldFunction(sha256.New()))
	assert.NoError(err)
	// Export solidity contract
	helper.ExportContract(vk, "Verify.sol")
	// Output verify data
	proofData, cmts, cmtPok := helper.GetContractInput(proof)
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
	}
}

func TestTemp(t *testing.T) {
	prevPhase1 := "Temp_Phase1_1"
	curPhase1 := "Temp_Phase1_2"
	finalPhase1 := "Temp_Phase1_final"
	_, err := mpc.InitPhase1(prevPhase1, 9)
	if err != nil {
		assert.Error(t, err)
	}
	mpc.ContributePhase1(prevPhase1, curPhase1)
	mpc.Seal(curPhase1, finalPhase1)

	var myCircuit TempCircuit
	css, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
	if err != nil {
		assert.Error(t, err)
	}

	prevPhase2 := "Temp_Phase2_1"
	curPhase2 := "Temp_Phase2_2"

	_, _, _, err = mpc.InitPhase2(css, finalPhase1, prevPhase2)
	_, phase2, err := mpc.ContributePhase2(prevPhase2, curPhase2)
	if err != nil {
		return
	}

	phase2.Seal()

	contractFilePath1 := "Verify_temp1.sol"
	contractFilePath2 := "Verify_temp2.sol"
	vkpath1 := "vk1_"
	vkpath2 := "vk2_"
	doWork(curPhase1, curPhase2, contractFilePath1, vkpath1)
	pk, vk, err := doWork(curPhase1, curPhase2, contractFilePath2, vkpath2)
	if err != nil {
		return
	}

	// Compute witness
	witness, err := frontend.NewWitness(&TempCircuit{Prev: 1, Currr: 1}, ecc.BN254.ScalarField())
	if err != nil {
		assert.Error(t, err)
	}
	proof, err := groth16.Prove(css.(*cs.R1CS), &pk, witness, backend.WithProverHashToFieldFunction(sha256.New()))
	if err != nil {
		assert.Error(t, err)
	}

	pubWitness, err := witness.Public()
	if err != nil {
		assert.Error(t, err)
	}
	err = groth16.Verify(proof, &vk, pubWitness.Vector().(fr_bn254.Vector), backend.WithVerifierHashToFieldFunction(sha256.New()))
	if err != nil {
		assert.Error(t, err)
	}

}

func doWork(path1, path2, contractFilePath, vkpath string) (pk groth16.ProvingKey, vk groth16.VerifyingKey, err error) {
	var myCircuit2 TempCircuit
	css2, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit2)
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
	}
	pk, vk, err = helper.GetInitParamsFromExistedMPCSetUp(css2, path1, path2)
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
	}

	f1, err := os.Create(vkpath + "1")
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
	}
	_, err = vk.WriteTo(f1)
	defer f1.Close()
	err = groth16.Setup(css2.(*cs.R1CS), &pk, &vk)
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
	}
	f2, err := os.Create(vkpath + "2")
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
	}
	_, err = vk.WriteTo(f2)
	defer f2.Close()
	helper.ExportContract(vk, contractFilePath)

	fmt.Printf("First File:")
	computeMd5(vkpath + "1")
	fmt.Printf("Second File:")
	computeMd5(vkpath + "2")

	return
}

func computeMd5(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	hash := md5.New()

	// 将文件内容复制到hash实例中
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	// 计算最终的MD5哈希值
	md5sum := hash.Sum(nil)
	// 将字节转换为16进制字符串
	fmt.Printf("MD5 of the file: %x\n", md5sum)
	return nil
}

type TempCircuit struct {
	Prev  frontend.Variable
	Currr frontend.Variable //`gnark:",public"`
}

// Define declares the circuit's constraints
// Hash = mimc(PreImage)
func (circuit *TempCircuit) Define(api frontend.API) error {
	// hash function
	api.AssertIsEqual(circuit.Prev, circuit.Currr)
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

func encodeMessages(encryptedFis [][]byte, bigRs []secp256k1.G1Affine, nonces [][]byte) [][]byte {
	result := make([][]byte, 0)
	for i := range encryptedFis {
		bigRBytes := bigRs[i].RawBytes()
		prefix := append(bigRBytes[:], nonces[i]...)
		result = append(result, append(prefix, encryptedFis[i]...))
	}
	return result
}
