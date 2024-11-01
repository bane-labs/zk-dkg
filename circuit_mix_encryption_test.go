package circom

import (
	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"math/big"
	"math/rand"
	"os"
	"testing"
	"time"
)

func Test_MixEncryption_Circuit(t *testing.T) {
	//generate a private key
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	privKey, err := ecies.GenerateKey(rand, crypto.S256(), nil)
	//generate a encrypt fragement key
	fiBytes, sfi, bfi, nonce, ctt, rs, rb := GenerateEncryptFragementKey(privKey.PublicKey)
	//computing proof
	_, circuit, witness, err := computingAssignment(privKey.PublicKey, rs, rb, fiBytes, sfi, bfi, ctt, nonce)
	err = test.IsSolved(&circuit, witness, ecc.BN254.ScalarField())
	assert := test.NewAssert(t)
	assert.NoError(err)
}

func TestMixEncryptionByMPC(t *testing.T) {
	//generate a private key
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	privKey, err := ecies.GenerateKey(rand, crypto.S256(), nil)
	//generate a encrypt fragement key
	fiBytes, sfi, bfi, nonce, ctt, rs, rb := GenerateEncryptFragementKey(privKey.PublicKey)
	//computing proof
	vk, proof, witness, err := GenerateProof(privKey.PublicKey, rs, rb, fiBytes, sfi, bfi, ctt, nonce)
	if err != nil {
		return
	}
	publicWitness, err := witness.Public()
	if err != nil {
		t.Fatalf(err.Error())
	}
	//verify proof
	err = groth16.Verify(proof, &vk, publicWitness.Vector().(fr_bn254.Vector))
	if err != nil {
		t.Fatalf(err.Error())
	}
	//print proof public msg
	// Save publicWitness
	/*	schema, _ := frontend.NewSchema(assignment)
		ret, _ := publicWitness.ToJSON(schema)
		var b bytes.Buffer
		json.Indent(&b, ret, "", "\t")
		t.Logf(b.String())*/
	// Save proof
	t.Logf("proof :,key:%x", proof.MarshalSolidity())
	//export solidity contract
	contract, err := os.Create("verify.sol")
	err = vk.ExportSolidity(contract)
	if err != nil {
		t.Fatalf(err.Error())
	}
	// solidity contract inputs
	proofBytes := proof.MarshalSolidity()
	fpSize := 4 * 8
	var prf [8]*big.Int
	// proof.Ar, proof.Bs, proof.Krs
	t.Logf("printf proof")
	for i := 0; i < 8; i++ {
		prf[i] = new(big.Int).SetBytes(proofBytes[fpSize*i : fpSize*(i+1)])
		t.Logf("proof:" + prf[i].String())
	}

	/*	c := new(big.Int).SetBytes(proofBytes[fpSize*8 : fpSize*8+4])
		commitmentCount := int(c.Int64())
		var commitmentPok [2]*big.Int

		// commitmentPok
		commitmentPok[0] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize : fpSize*8+4+2*commitmentCount*fpSize+fpSize])
		commitmentPok[1] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize+fpSize : fpSize*8+4+2*commitmentCount*fpSize+2*fpSize])
		t.Logf("printf commitmentPok")
		t.Logf("commitmentPok 0:" + commitmentPok[0].String())
		t.Logf("commitmentPok 1:" + commitmentPok[1].String())

		var commitments [{{mul 2.NbCommitments}}]*big.Int
		// commitments
		t.Logf("printf commitments")
		for i := 0; i < 2*commitmentCount; i++ {
		commitments[i] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+i*fpSize: fpSize*8+4+(i+1)*fpSize])
		t.Logf("commitments:"+commitments[i])
		}*/
}
