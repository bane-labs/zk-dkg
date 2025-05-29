package zkdkg

import (
	crypto_rand "crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/bane-labs/zk-dkg/circuit"
	"github.com/bane-labs/zk-dkg/helper"
	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark/backend/plonk"
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
	innerCSSPath := "inner_ccs_" + strconv.Itoa(batch)
	innerPKPath := "inner_pk_" + strconv.Itoa(batch)
	innerVKPath := "inner_vk_" + strconv.Itoa(batch)
	innerCSS, err := helper.ReadCSS(innerCSSPath)
	assert.NoError(err)
	innerPK, err := helper.ReadPlonkProvingKey(innerPKPath, ecc.BN254)
	assert.NoError(err)
	innerVK, err := helper.ReadPlonkVerifyingKey(innerVKPath, ecc.BN254)
	assert.NoError(err)

	outerCSSPath := "outer_ccs"
	outerPKPath := "outer_pk"
	outerVKPath := "outer_vk"
	outerCSS, err := helper.ReadCSS(outerCSSPath)
	assert.NoError(err)
	outerPK, err := helper.ReadPlonkProvingKey(outerPKPath, ecc.BN254)
	assert.NoError(err)
	outerVK, err := helper.ReadPlonkVerifyingKey(outerVKPath, ecc.BN254)
	assert.NoError(err)

	// Compute proof
	proof, witness, err := ProveMultipleKeyShareEncryption(outerCSS, outerPK, innerCSS, innerPK, innerVK, pubKeys, rs, bigRs, fisBytes, fisInts, bigFis, encryptedFis, nonces)
	assert.NoError(err)
	// Verify proof
	publicWitness, err := witness.Public()
	assert.NoError(err)
	err = plonk.Verify(proof, outerVK, publicWitness)
	assert.NoError(err)
	output := helper.GetContractInput(proof)
	fmt.Println("Plonk proof is", "0x"+hex.EncodeToString(output))
}

func TestTwoRecoverMessageGeneration(t *testing.T) {
	assert := test.NewAssert(t)
	// Generate node private key
	var batch = 2
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	// Compute public key
	fis := make([]*fr_bls12381.Element, batch)
	pubKeys := make([]*ecies.PublicKey, batch)
	for i := 0; i < batch; i++ {
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
	for i := 0; i < batch; i++ {
		t.Logf("Share message: %s", hex.EncodeToString(messages[i]))
	}
	// Read files
	innerCSSPath := "inner_ccs_" + strconv.Itoa(batch)
	innerPKPath := "inner_pk_" + strconv.Itoa(batch)
	innerVKPath := "inner_vk_" + strconv.Itoa(batch)
	innerCSS, err := helper.ReadCSS(innerCSSPath)
	assert.NoError(err)
	innerPK, err := helper.ReadPlonkProvingKey(innerPKPath, ecc.BN254)
	assert.NoError(err)
	innerVK, err := helper.ReadPlonkVerifyingKey(innerVKPath, ecc.BN254)
	assert.NoError(err)

	outerCSSPath := "outer_ccs"
	outerPKPath := "outer_pk"
	outerVKPath := "outer_vk"
	outerCSS, err := helper.ReadCSS(outerCSSPath)
	assert.NoError(err)
	outerPK, err := helper.ReadPlonkProvingKey(outerPKPath, ecc.BN254)
	assert.NoError(err)
	outerVK, err := helper.ReadPlonkVerifyingKey(outerVKPath, ecc.BN254)
	assert.NoError(err)

	// Compute proof
	proof, witness, err := ProveMultipleKeyShareEncryption(outerCSS, outerPK, innerCSS, innerPK, innerVK, pubKeys, rs, bigRs, fisBytes, fisInts, bigFis, encryptedFis, nonces)
	assert.NoError(err)
	// Verify proof
	publicWitness, err := witness.Public()
	assert.NoError(err)
	err = plonk.Verify(proof, outerVK, publicWitness)
	assert.NoError(err)
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
