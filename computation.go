package circom

import (
	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	fr_secp "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"golang.org/x/crypto/sha3"
	"math/big"
)

func GenerateFragementKey() (fiBytes []byte, sfi big.Int, bfi bls12381.G1Affine) {
	var fi fr_bls12381.Element
	_, _ = fi.SetRandom()
	fi.BigInt(&sfi)
	fiBytes = make([]byte, 32)
	sfi.FillBytes(fiBytes)
	_, _, g12381, _ := bls12381.Generators()
	bfi.ScalarMultiplication(&g12381, &sfi)
	return
}
func GenerateEncryptFragementKey(pb ecies.PublicKey) (fiBytes []byte, sfi big.Int, bfi bls12381.G1Affine, nonce []byte, ctt []byte, rs big.Int, rb secp256k1.G1Affine) {
	fiBytes, sfi, bfi = GenerateFragementKey()
	nonce, ctt, rs, rb = Encrypt(pb, fiBytes)
	return
}

func GetHash(data []byte) []byte {
	hashBuilder := sha3.New256()
	hashBuilder.Write(data)
	return hashBuilder.Sum(nil)
}

func GenerateProof(phase1Path string, phase2Path string, pubKey ecies.PublicKey, rs big.Int, rb secp256k1.G1Affine, fiBytes []byte, sfi big.Int, bfi bls12381.G1Affine, ctt []byte, nonce []byte) (vk groth16.VerifyingKey, proof *groth16.Proof, witness witness.Witness, err error) {
	css, _, assignment, err := computingAssignment(pubKey, rs, rb, fiBytes, sfi, bfi, ctt, nonce)
	if err != nil {
		return groth16.VerifyingKey{}, nil, nil, err
	}
	if err != nil {
		return groth16.VerifyingKey{}, nil, nil, err
	}
	_, vk, proof, witness, err = computingProof(phase1Path, phase2Path, css, assignment)
	if err != nil {
		return groth16.VerifyingKey{}, nil, nil, err
	}
	return
}

func computingAssignment(pubKey ecies.PublicKey, rs big.Int, rb secp256k1.G1Affine, fiBytes []byte, sfi big.Int, bfi bls12381.G1Affine, ctt []byte, nonce []byte) (css constraint.ConstraintSystem, circuit MixEncryptionWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], assignment *MixEncryptionWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], err error) {
	//data format
	plainChunksBytes := make([]frontend.Variable, len(fiBytes))
	for i := 0; i < len(fiBytes); i++ {
		plainChunksBytes[i] = fiBytes[i]
	}
	ciphertextBytes := make([]frontend.Variable, len(ctt))
	for i := 0; i < len(ctt); i++ {
		ciphertextBytes[i] = ctt[i]
	}
	nonceBytes := [12]frontend.Variable{}
	for i := 0; i < len(nonce); i++ {
		nonceBytes[i] = nonce[i]
	}
	var px fp.Element
	px.SetBigInt(pubKey.X)
	var py fp.Element
	py.SetBigInt(pubKey.Y)
	Pub := secp256k1.G1Affine{
		px,
		py,
	}
	//get RPub
	var RPub secp256k1.G1Affine
	RPub.ScalarMultiplication(&Pub, &rs)
	//get allHash
	nbBytes := 2 * fr_secp.Bytes
	rawBigR := rb.RawBytes()
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
	rawFi := bfi.RawBytes()
	RawFi := make([]byte, 2*fr_secp.Bytes*8)
	for i := 0; i < nbBytes; i++ {
		for j := 0; j < 8; j++ {
			RawFi[i*8+j] = (rawFi[i] >> (7 - j)) & 1
		}
	}
	temp := append(append(append(append(append(RawBigR, RawPub...), RawFi...), nonce...), 2), ctt...)
	raw_allHash := GetHash(temp)
	allHash := make([]frontend.Variable, len(raw_allHash))
	for i := 0; i < len(allHash); i++ {
		allHash[i] = raw_allHash[i]
	}

	//proof
	circuit = MixEncryptionWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		PlainChunks:  make([]frontend.Variable, len(plainChunksBytes)),
		CipherChunks: make([]frontend.Variable, len(ciphertextBytes)),
		AllHash:      make([]frontend.Variable, len(allHash)),
	}
	css, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, circuit, nil, err
	}

	assignment = &MixEncryptionWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		SmallR: emulated.ValueOf[emulated.Secp256k1Fr](rs),
		BigR: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](rb.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](rb.Y),
		},
		Pub: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](Pub.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](Pub.Y),
		},
		RPub: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](RPub.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](RPub.Y),
		},
		PlainChunks:  plainChunksBytes,
		Iv:           nonceBytes,
		ChunkIndex:   2,
		CipherChunks: ciphertextBytes,

		SmallFi: emulated.ValueOf[emulated.BLS12381Fr](sfi),
		Fi: sw_emulated.AffinePoint[emulated.BLS12381Fp]{
			X: emulated.ValueOf[emulated.BLS12381Fp](bfi.X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](bfi.Y),
		},
		AllHash: allHash,
	}
	return
}

func computingProof[T1, S1, T2, S2 emulated.FieldParams](phase1Path string, phase2Path string, css constraint.ConstraintSystem, assignment *MixEncryptionWrapper[T1, S1, T2, S2]) (pk groth16.ProvingKey, vk groth16.VerifyingKey, proof *groth16.Proof, witness witness.Witness, err error) {
	//init,2ways: way1 make a new mpc, way2 from a existed mpc
	//pk, vk, _ = doMPCSetUp(css, 3, 3, 21)
	pk, vk, _ = GetFromExistedMPCSetUp(css, phase1Path, phase2Path)
	// 1. One time setup
	err = groth16.Setup(css.(*cs.R1CS), &pk, &vk)
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, nil, nil, err
	}
	//compute witness
	witness, err = frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, nil, nil, err
	}
	// compute proof
	proof, err = groth16.Prove(css.(*cs.R1CS), &pk, witness)
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, nil, nil, err
	}
	return
}

func GetFromExistedMPCSetUp(ccs constraint.ConstraintSystem, phase1Path string, phase2Path string) (pk groth16.ProvingKey, vk groth16.VerifyingKey, err error) {
	srs1, err := ReadPhase1FromFile(phase1Path)
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
	}
	// Prepare for phase-1.5
	var evals mpcsetup.Phase2Evaluations
	r1cs := ccs.(*cs.R1CS)
	// Prepare for phase-2
	_, evals = mpcsetup.InitPhase2(r1cs, &srs1)

	srs2, err := ReadPhase2FromFile(phase2Path)
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
	}
	// Extract the proving and verifying keys
	pk, vk = mpcsetup.ExtractKeys(&srs1, &srs2, &evals, ccs.GetNbConstraints())
	return pk, vk, nil
}
