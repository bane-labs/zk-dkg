package zkdkg

import (
	crypto_rand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"math/rand"
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
	data := helper.GetOutputData(proof)
	data.Printf()
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
