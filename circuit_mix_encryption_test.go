package circom

import (
	"bytes"
	"encoding/json"
	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	fr_secp "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"golang.org/x/crypto/sha3"
	"math/big"
	"math/rand"
	"os"
	"strconv"
	"testing"
	"time"
)

func Test_MixEncryption_Circuit(t *testing.T) {
	//check BigR=rG
	_, g := secp256k1.Generators()
	var r fr_secp.Element
	_, _ = r.SetRandom()
	SmallR := new(big.Int)
	r.BigInt(SmallR)
	var BigR secp256k1.G1Affine
	BigR.ScalarMultiplication(&g, SmallR)
	//generator PublicKey
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	privKey, err := ecies.GenerateKey(rand, crypto.S256(), nil)
	if err != nil {
		return
	}
	var px fp.Element
	px.SetInterface(privKey.PublicKey.X)
	var py fp.Element
	py.SetInterface(privKey.PublicKey.Y)
	Pub := secp256k1.G1Affine{
		px,
		py,
	}
	//generator RPub=r*PublicKey
	var RPub secp256k1.G1Affine
	RPub.ScalarMultiplication(&Pub, SmallR)
	RawRpub := RPub.RawBytes()
	//generator key=hash(RPub)
	nbBytes := 2 * fr_secp.Bytes
	key := make([]byte, nbBytes*8)
	for i := 0; i < nbBytes; i++ {
		for j := 0; j < 8; j++ {
			key[i*8+j] = (RawRpub[i] >> (7 - j)) & 1
		}
	}
	hasher := sha3.New256()
	hasher.Write(key)
	expected := hasher.Sum(nil)
	keyBytes := [32]frontend.Variable{}
	for i := 0; i < len(expected); i++ {
		keyBytes[i] = expected[i]
	}
	//aes
	var fi fr_bls12381.Element
	_, _ = fi.SetRandom()
	SmallFi := new(big.Int)
	fi.BigInt(SmallFi)
	//message
	var m [32]byte
	SmallFi.FillBytes(m[:])
	PlainChunksBytes := make([]frontend.Variable, len(m))
	for i := 0; i < len(m); i++ {
		PlainChunksBytes[i] = m[i]
	}
	ciphertext, nonce := AesGcmEncrypt(expected, m[:])
	Ciphertext_bytes := make([]frontend.Variable, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		Ciphertext_bytes[i] = ciphertext[i]
	}
	nonceBytes := [12]frontend.Variable{}
	for i := 0; i < len(nonce); i++ {
		nonceBytes[i] = nonce[i]
	}
	//Fi=fiG
	_, _, g12381, _ := bls12381.Generators()
	var Fi bls12381.G1Affine
	Fi.ScalarMultiplication(&g12381, SmallFi)

	//get allHash
	rawBigR := BigR.RawBytes()
	RawBigR := make([]byte, 2*fr_secp.Bytes*8)
	for i := 0; i < nbBytes; i++ {
		for j := 0; j < 8; j++ {
			RawBigR[i*8+j] = (rawBigR[i] >> (7 - j)) & 1
		}
	}
	rawPub := Pub.RawBytes()
	RawPub := make([]byte, 2*fr_secp.Bytes*8)
	for i := 0; i < nbBytes; i++ {
		for j := 0; j < 8; j++ {
			RawPub[i*8+j] = (rawPub[i] >> (7 - j)) & 1
		}
	}
	rawFi := Fi.RawBytes()
	RawFi := make([]byte, 2*fr_secp.Bytes*8)
	for i := 0; i < nbBytes; i++ {
		for j := 0; j < 8; j++ {
			RawFi[i*8+j] = (rawFi[i] >> (7 - j)) & 1
		}
	}
	temp := append(append(append(append(append(RawBigR, RawPub...), RawFi...), nonce...), 2), ciphertext...)

	hasher2 := sha3.New256()
	hasher2.Write(temp)
	raw_allHash := hasher2.Sum(nil)
	allHash := make([]frontend.Variable, len(raw_allHash))
	for i := 0; i < len(allHash); i++ {
		allHash[i] = raw_allHash[i]
	}
	/*	goMimc := hash.MIMC_BN254.New()
		for i := 0; i < 10; i++ {
			goMimc.Write(temp)
		}
		allHash := goMimc.Sum(nil)*/
	//proof
	circuit := MixEncryptionWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		PlainChunks:  make([]frontend.Variable, len(PlainChunksBytes)),
		CipherChunks: make([]frontend.Variable, len(Ciphertext_bytes)),
		AllHash:      make([]frontend.Variable, len(allHash)),
	}
	witness := MixEncryptionWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		SmallR: emulated.ValueOf[emulated.Secp256k1Fr](SmallR),
		BigR: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](BigR.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](BigR.Y),
		},
		Pub: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](Pub.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](Pub.Y),
		},
		RPub: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](RPub.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](RPub.Y),
		},
		PlainChunks:  PlainChunksBytes,
		Iv:           nonceBytes,
		ChunkIndex:   2,
		CipherChunks: Ciphertext_bytes,

		SmallFi: emulated.ValueOf[emulated.BLS12381Fr](SmallFi),
		Fi: sw_emulated.AffinePoint[emulated.BLS12381Fp]{
			X: emulated.ValueOf[emulated.BLS12381Fp](Fi.X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](Fi.Y),
		},
		AllHash: allHash,
	}
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert := test.NewAssert(t)
	assert.NoError(err)
}

func TestMixEncryptionByMPC(t *testing.T) {
	//check BigR=rG
	_, g := secp256k1.Generators()
	var r fr_secp.Element
	_, _ = r.SetRandom()
	SmallR := new(big.Int)
	r.BigInt(SmallR)
	var BigR secp256k1.G1Affine
	BigR.ScalarMultiplication(&g, SmallR)
	//generator PublicKey
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	privKey, err := ecies.GenerateKey(rand, crypto.S256(), nil)
	if err != nil {
		return
	}
	var px fp.Element
	px.SetInterface(privKey.PublicKey.X)
	var py fp.Element
	py.SetInterface(privKey.PublicKey.Y)
	Pub := secp256k1.G1Affine{
		px,
		py,
	}
	//generator RPub=r*PublicKey
	var RPub secp256k1.G1Affine
	RPub.ScalarMultiplication(&Pub, SmallR)
	RawRpub := RPub.RawBytes()
	//generator key=hash(RPub)
	nbBytes := 2 * fr_secp.Bytes
	key := make([]byte, nbBytes*8)
	for i := 0; i < nbBytes; i++ {
		for j := 0; j < 8; j++ {
			key[i*8+j] = (RawRpub[i] >> (7 - j)) & 1
		}
	}
	hasher := sha3.New256()
	hasher.Write(key)
	expected := hasher.Sum(nil)
	keyBytes := [32]frontend.Variable{}
	for i := 0; i < len(expected); i++ {
		keyBytes[i] = expected[i]
	}
	var fi fr_bls12381.Element
	_, _ = fi.SetRandom()
	//aes
	SmallFi := new(big.Int)
	fi.BigInt(SmallFi)
	//message
	var m [32]byte
	SmallFi.FillBytes(m[:])
	PlainChunksBytes := make([]frontend.Variable, len(m))
	for i := 0; i < len(m); i++ {
		PlainChunksBytes[i] = m[i]
	}
	ciphertext, nonce := AesGcmEncrypt(expected, m[:])
	Ciphertext_bytes := make([]frontend.Variable, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		Ciphertext_bytes[i] = ciphertext[i]
	}
	nonceBytes := [12]frontend.Variable{}
	for i := 0; i < len(nonce); i++ {
		nonceBytes[i] = nonce[i]
	}
	//Fi=fiG
	_, _, g12381, _ := bls12381.Generators()
	var Fi bls12381.G1Affine
	Fi.ScalarMultiplication(&g12381, SmallFi)

	//get allHash
	rawBigR := BigR.RawBytes()
	RawBigR := make([]byte, 2*fr_secp.Bytes*8)
	for i := 0; i < nbBytes; i++ {
		for j := 0; j < 8; j++ {
			RawBigR[i*8+j] = (rawBigR[i] >> (7 - j)) & 1
		}
	}
	rawPub := Pub.RawBytes()
	RawPub := make([]byte, 2*fr_secp.Bytes*8)
	for i := 0; i < nbBytes; i++ {
		for j := 0; j < 8; j++ {
			RawPub[i*8+j] = (rawPub[i] >> (7 - j)) & 1
		}
	}
	rawFi := Fi.RawBytes()
	RawFi := make([]byte, 2*fr_secp.Bytes*8)
	for i := 0; i < nbBytes; i++ {
		for j := 0; j < 8; j++ {
			RawFi[i*8+j] = (rawFi[i] >> (7 - j)) & 1
		}
	}
	temp := append(append(append(append(append(RawBigR, RawPub...), RawFi...), nonce...), 2), ciphertext...)

	hasher2 := sha3.New256()
	hasher2.Write(temp)
	raw_allHash := hasher2.Sum(nil)
	allHash := make([]frontend.Variable, len(raw_allHash))
	for i := 0; i < len(allHash); i++ {
		allHash[i] = raw_allHash[i]
	}
	//proof
	circuit := MixEncryptionWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		PlainChunks:  make([]frontend.Variable, len(PlainChunksBytes)),
		CipherChunks: make([]frontend.Variable, len(Ciphertext_bytes)),
		AllHash:      make([]frontend.Variable, len(allHash)),
	}
	css, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf(err.Error())
	}
	//init,2ways: way1 make a new mpc, way2 from a existed mpc
	pk, vk, _ := doMPCSetUp(css, 3, 3, 21)
	//pk, vk, _ := getFromExistedMPCSetUp(css)
	// 1. One time setup
	err = groth16.Setup(css.(*cs.R1CS), &pk, &vk)
	if err != nil {
		t.Fatalf(err.Error())
	}
	assignment := &MixEncryptionWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		SmallR: emulated.ValueOf[emulated.Secp256k1Fr](SmallR),
		BigR: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](BigR.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](BigR.Y),
		},
		Pub: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](Pub.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](Pub.Y),
		},
		RPub: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](RPub.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](RPub.Y),
		},
		PlainChunks:  PlainChunksBytes,
		Iv:           nonceBytes,
		ChunkIndex:   2,
		CipherChunks: Ciphertext_bytes,

		SmallFi: emulated.ValueOf[emulated.BLS12381Fr](SmallFi),
		Fi: sw_emulated.AffinePoint[emulated.BLS12381Fp]{
			X: emulated.ValueOf[emulated.BLS12381Fp](Fi.X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](Fi.Y),
		},
		AllHash: allHash,
	}
	//compute witness
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf(err.Error())
	}
	publicWitness, err := witness.Public()
	if err != nil {
		t.Fatalf(err.Error())
	}
	// compute proof
	proof, err := groth16.Prove(css.(*cs.R1CS), &pk, witness)
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
	schema, _ := frontend.NewSchema(assignment)
	ret, _ := publicWitness.ToJSON(schema)
	var b bytes.Buffer
	json.Indent(&b, ret, "", "\t")
	t.Logf(b.String())
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

// nContributionsPhase1 = 3
// nContributionsPhase2 = 3
// power                = 21 //element count range 2^0-2^27
func doMPCSetUp(ccs constraint.ConstraintSystem, nContributionsPhase1 int, nContributionsPhase2 int, power int) (pk groth16.ProvingKey, vk groth16.VerifyingKey, err error) {
	_, err = InitPhase1("Phase1_1", power)
	if err != nil {
		return pk, vk, err
	}
	// All members build and verify contributions for phase1
	for i := 1; i < nContributionsPhase1; i++ {
		prepath := "Phase1_" + strconv.Itoa(i)
		nextPath := "Phase1_" + strconv.Itoa(i+1)
		_, _, err := ContributePhase1(prepath, nextPath)
		if err != nil {
			return pk, vk, err
		}
	}
	evals, srs1, _, err := InitPhase2(ccs, "Phase1_"+strconv.Itoa(nContributionsPhase1), "Phase2_1")
	if err != nil {
		return pk, vk, err
	}
	// All members build and verify contributions for phase2
	for i := 1; i < nContributionsPhase2; i++ {
		prepath := "Phase2_" + strconv.Itoa(i)
		nextPath := "Phase2_" + strconv.Itoa(i+1)
		_, _, err := ContributePhase2(prepath, nextPath)
		if err != nil {
			panic(err)
		}
	}
	srs2, err := ReadPhase2FromFile("Phase2_" + strconv.Itoa(nContributionsPhase1))
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
	}
	// Extract the proving and verifying keys
	pk, vk = mpcsetup.ExtractKeys(&srs1, &srs2, &evals, ccs.GetNbConstraints())
	return pk, vk, nil
}

func getFromExistedMPCSetUp(ccs constraint.ConstraintSystem) (pk groth16.ProvingKey, vk groth16.VerifyingKey, err error) {
	srs1, err := ReadPhase1FromFile("Phase1_" + strconv.Itoa(3))
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
	}
	// Prepare for phase-1.5
	var evals mpcsetup.Phase2Evaluations
	r1cs := ccs.(*cs.R1CS)
	// Prepare for phase-2
	_, evals = mpcsetup.InitPhase2(r1cs, &srs1)

	srs2, err := ReadPhase2FromFile("Phase2_" + strconv.Itoa(3))
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
	}
	// Extract the proving and verifying keys
	pk, vk = mpcsetup.ExtractKeys(&srs1, &srs2, &evals, ccs.GetNbConstraints())
	return pk, vk, nil
}
