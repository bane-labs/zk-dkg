package circuit

import (
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"math/big"

	"github.com/bane-labs/zk-dkg/helper"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

/**
 * Function: ComputeSingleKeyShareEncryptionAssignment
 * @Description: get input data collection for a zk proof calculation of a key share generating process
 * @param pubKey: public key used for key share encryption
 * @param r: the integer format of random number
 * @param bigR: the corresponding elliptic curve point of random number
 * @param fiBytes: the key share in a byte array
 * @param fiInt: the integer format of the key share
 * @param bigFi: the bls12381 commitment of the key share
 * @param encryptedFi: the encrypted key
 * @param nonce: salt
 * @return css: circuit constraints
 * @return circuit: circuit
 * @return assignment: input data collection
 * @return err: error
 */
func ComputeSingleKeyShareEncryptionAssignment(pubKey *ecies.PublicKey, r big.Int, bigR secp256k1.G1Affine, fiBytes []byte, fiInt big.Int, bigFi bls12381.G1Affine, encryptedFi []byte, nonce []byte) *ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr] {
	// Format data
	plainChunksBytes := make([]frontend.Variable, len(fiBytes))
	for i := 0; i < len(fiBytes); i++ {
		plainChunksBytes[i] = fiBytes[i]
	}
	ciphertextBytes := make([]frontend.Variable, len(encryptedFi))
	for i := 0; i < len(encryptedFi); i++ {
		ciphertextBytes[i] = encryptedFi[i]
	}
	nonceBytes := [12]frontend.Variable{}
	for i := 0; i < len(nonce); i++ {
		nonceBytes[i] = nonce[i]
	}
	var px fp.Element
	px.SetBigInt(pubKey.X)
	var py fp.Element
	py.SetBigInt(pubKey.Y)
	pub := secp256k1.G1Affine{
		X: px,
		Y: py,
	}
	// Compute RPub
	var rPub secp256k1.G1Affine
	rPub.ScalarMultiplication(&pub, &r)
	// Compute allHash
	secp256k1G1ByteLength := secp256k1.SizeOfG1AffineUncompressed
	bls12381G1ByteLength := bls12381.SizeOfG1AffineUncompressed
	bigRBytes := bigR.RawBytes()
	rawBigR := make([]byte, secp256k1G1ByteLength*8)
	for i := 0; i < secp256k1G1ByteLength; i++ {
		for j := 0; j < 8; j++ {
			rawBigR[i*8+j] = (bigRBytes[i] >> (7 - j)) & 1
		}
	}
	pubBytes := pub.RawBytes()
	rawPub := make([]byte, secp256k1G1ByteLength*8)
	for i := 0; i < secp256k1G1ByteLength; i++ {
		for j := 0; j < 8; j++ {
			rawPub[i*8+j] = (pubBytes[i] >> (7 - j)) & 1
		}
	}
	bigFiBytes := bigFi.RawBytes()
	rawBigFi := make([]byte, bls12381G1ByteLength*8)
	for i := 0; i < bls12381G1ByteLength; i++ {
		for j := 0; j < 8; j++ {
			rawBigFi[i*8+j] = (bigFiBytes[i] >> (7 - j)) & 1
		}
	}
	temp := append(append(append(append(append(rawBigR, rawPub...), rawBigFi...), nonce...), 2), encryptedFi...)
	sumHash := helper.GetHash(temp)
	rawSumHash := make([]frontend.Variable, len(sumHash))
	for i := 0; i < len(rawSumHash); i++ {
		rawSumHash[i] = sumHash[i]
	}
	return &ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		SmallR: emulated.ValueOf[emulated.Secp256k1Fr](r),
		BigR: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](bigR.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](bigR.Y),
		},
		Pub: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pub.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](pub.Y),
		},
		RPub: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](rPub.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](rPub.Y),
		},
		PlainChunks:  plainChunksBytes,
		Iv:           nonceBytes,
		ChunkIndex:   2,
		CipherChunks: ciphertextBytes,

		SmallFi: emulated.ValueOf[emulated.BLS12381Fr](fiInt),
		Fi: sw_emulated.AffinePoint[emulated.BLS12381Fp]{
			X: emulated.ValueOf[emulated.BLS12381Fp](bigFi.X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](bigFi.Y),
		},
		PubInputHash: rawSumHash,
	}
}

func ComputeSingleKeyShareEncryptionCircuit(fiBytes []byte, encryptedFi []byte) *ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr] {

	circuit := &ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		PlainChunks:  make([]frontend.Variable, len(fiBytes)),
		CipherChunks: make([]frontend.Variable, len(encryptedFi)),
		PubInputHash: make([]frontend.Variable, 32),
	}
	return circuit
}

func ComputeSingleKeyShareEncryptionCircuitByFile(ccsPath, pkPath, vkPath string) (constraint.ConstraintSystem, *groth16.ProvingKey, *groth16.VerifyingKey) {
	ccs, err := helper.ReadCSS(ccsPath)
	if err != nil {
		panic(err)
	}
	pK, err := helper.ReadProvingKey(pkPath)
	if err != nil {
		panic(err)
	}
	vK, err := helper.ReadVerifyingKey(vkPath)
	if err != nil {
		panic(err)
	}
	return ccs, pK, vK
}

func ComputeMultipleKeyShareEncryptionAssignment(batch int, pubKey []*ecies.PublicKey, rs []big.Int, bigRs []secp256k1.G1Affine, fisBytes [][]byte, fisInts []big.Int, bigFis []bls12381.G1Affine, encryptedFis [][]byte, nonces [][]byte) []*ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr] {
	assignments := make([]*ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], batch)
	for i := 0; i < batch; i++ {
		assignments[i] = ComputeSingleKeyShareEncryptionAssignment(pubKey[i], rs[i], bigRs[i], fisBytes[i], fisInts[i], bigFis[i], encryptedFis[i], nonces[i])

	}
	return assignments
}

func ComputeMultipleKeyShareEncryptionCircuitByFile(batch int, ccsPath, pkPath, vkPath string) ([]constraint.ConstraintSystem, []*groth16.ProvingKey, []*groth16.VerifyingKey) {
	ccss := make([]constraint.ConstraintSystem, batch)
	pks := make([]*groth16.ProvingKey, batch)
	vks := make([]*groth16.VerifyingKey, batch)

	innerCcs, innerPK, innerVK := ComputeSingleKeyShareEncryptionCircuitByFile(ccsPath, pkPath, vkPath)

	for i := 0; i < batch; i++ {
		ccss[i] = innerCcs
		pks[i] = innerPK
		vks[i] = innerVK
	}
	return ccss, pks, vks
}

func ComputeRecursionEncryptionCircuit(batch int, innerCcss []constraint.ConstraintSystem, innerVKs []*groth16.VerifyingKey) *RecursionEncryptionWrapper[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl] {
	circuitVk := make([]stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl], batch)
	for i := 0; i < batch; i++ {
		// initialize the witness elements
		var err error
		circuitVk[i], err = stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVKs[i])
		if err != nil {
			panic(err)
		}
	}
	outerCircuit := &RecursionEncryptionWrapper[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness: make([]stdgroth16.Witness[sw_bn254.ScalarField], batch),
		VerifyingKey: circuitVk,
		Proof:        make([]stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine], batch),
		CommentsHash: make([]frontend.Variable, 32),
	}

	for i := 0; i < batch; i++ {
		outerCircuit.InnerWitness[i] = stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcss[i])
		outerCircuit.Proof[i] = stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcss[i])
	}
	return outerCircuit
}

func ComputeRecursionEncryptionAssignment(field, outer *big.Int, batch int, innerCcss []constraint.ConstraintSystem, innerPKs []*groth16.ProvingKey, innerVKs []*groth16.VerifyingKey, innerAssignments []*ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], commentsHash []frontend.Variable) *RecursionEncryptionWrapper[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl] {
	//innerCcss, innerPKs, innerVKs := ComputeMultipleKeyShareEncryptionCircuitByFile(batch, ccsPath, pkPath, vkPath)
	innerProofs, innerWitness := ComputeInnerProofs(field, outer, batch, innerCcss, innerPKs, innerVKs, innerAssignments)
	circuitVk := make([]stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl], batch)
	circuitWitness := make([]stdgroth16.Witness[sw_bn254.ScalarField], batch)
	circuitProof := make([]stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine], batch)
	for i := 0; i < batch; i++ {
		// initialize the witness elements
		var err error
		circuitVk[i], err = stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVKs[i])
		if err != nil {
			panic(err)
		}
		circuitWitness[i], err = stdgroth16.ValueOfWitness[sw_bn254.ScalarField](innerWitness[i])
		if err != nil {
			panic(err)
		}
		circuitProof[i], err = stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerProofs[i])
		if err != nil {
			panic(err)
		}
	}

	outerAssignment := &RecursionEncryptionWrapper[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		CommentsHash: commentsHash,
	}
	return outerAssignment
}

func ComputeInnerProof(field, outer *big.Int, innerccs constraint.ConstraintSystem, innerPK *groth16.ProvingKey, innerVK *groth16.VerifyingKey, innerAssignment *ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]) (*groth16.Proof, witness.Witness) {
	r1cs := innerccs.(*cs.R1CS)
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	if err != nil {
		panic(err)
	}
	innerPubWitness, err := innerWitness.Public()
	if err != nil {
		panic(err)
	}
	innerProof, err := groth16.Prove(r1cs, innerPK, innerWitness, stdgroth16.GetNativeProverOptions(outer, field))
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(innerProof, innerVK, innerPubWitness.Vector().(fr_bn254.Vector), stdgroth16.GetNativeVerifierOptions(outer, field))
	if err != nil {
		panic(err)
	}

	return innerProof, innerPubWitness
}

func ComputeInnerProofs(field, outer *big.Int, batch int, innerccss []constraint.ConstraintSystem, innerPKs []*groth16.ProvingKey, innerVKs []*groth16.VerifyingKey, innerAssignments []*ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]) ([]*groth16.Proof, []witness.Witness) {
	innerPubWitnesss := make([]witness.Witness, batch)
	innerProofs := make([]*groth16.Proof, batch)

	for i := 0; i < batch; i++ {
		innerProof, innerPubWitness := ComputeInnerProof(field, outer, innerccss[i], innerPKs[i], innerVKs[i], innerAssignments[i])
		innerPubWitnesss[i] = innerPubWitness
		innerProofs[i] = innerProof
	}
	return innerProofs, innerPubWitnesss
}

func ComputeCommHash(batch int, pubKey []*ecies.PublicKey, rs []big.Int, bigRs []secp256k1.G1Affine, fisBytes [][]byte, bigFis []bls12381.G1Affine, encryptedFis [][]byte, nonces [][]byte) []frontend.Variable {
	allHash := make([]byte, 0)
	for index := 0; index < batch; index++ {
		// Format data
		plainChunksBytes := make([]frontend.Variable, len(fisBytes[index]))
		for i := 0; i < len(fisBytes[index]); i++ {
			plainChunksBytes[i] = fisBytes[index][i]
		}
		ciphertextBytes := make([]frontend.Variable, len(encryptedFis[index]))
		for i := 0; i < len(encryptedFis[index]); i++ {
			ciphertextBytes[i] = encryptedFis[index][i]
		}
		noncesBytes := [12]frontend.Variable{}
		for i := 0; i < len(nonces[index]); i++ {
			noncesBytes[i] = nonces[index][i]
		}
		var px fp.Element
		px.SetBigInt(pubKey[index].X)
		var py fp.Element
		py.SetBigInt(pubKey[index].Y)
		pub := secp256k1.G1Affine{
			X: px,
			Y: py,
		}
		// Compute RPub
		var rPub secp256k1.G1Affine
		rPub.ScalarMultiplication(&pub, &rs[index])
		// Compute allHash
		secp256k1G1ByteLength := secp256k1.SizeOfG1AffineUncompressed
		bls12381G1ByteLength := bls12381.SizeOfG1AffineUncompressed
		bigRBytes := bigRs[index].RawBytes()
		rawBigR := make([]byte, secp256k1G1ByteLength*8)
		for i := 0; i < secp256k1G1ByteLength; i++ {
			for j := 0; j < 8; j++ {
				rawBigR[i*8+j] = (bigRBytes[i] >> (7 - j)) & 1
			}
		}
		pubBytes := pub.RawBytes()
		rawPub := make([]byte, secp256k1G1ByteLength*8)
		for i := 0; i < secp256k1G1ByteLength; i++ {
			for j := 0; j < 8; j++ {
				rawPub[i*8+j] = (pubBytes[i] >> (7 - j)) & 1
			}
		}
		bigFisBytes := bigFis[index].RawBytes()
		rawBigFis := make([]byte, bls12381G1ByteLength*8)
		for i := 0; i < bls12381G1ByteLength; i++ {
			for j := 0; j < 8; j++ {
				rawBigFis[i*8+j] = (bigFisBytes[i] >> (7 - j)) & 1
			}
		}
		rawPubInputs := make([]byte, 0)
		rawPubInputs = append(rawPubInputs, append(append(append(append(append(rawBigR, rawPub...), rawBigFis...), nonces[index]...), 2), encryptedFis[index]...)...)

		allHash = append(allHash, helper.GetHash(rawPubInputs)...)
	}

	commonHash := helper.GetHash(allHash)
	rawSumHash := make([]frontend.Variable, len(commonHash))
	for i := 0; i < len(commonHash); i++ {
		rawSumHash[i] = commonHash[i]
	}
	return rawSumHash
}
