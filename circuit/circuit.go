package circuit

import (
	"math/big"

	"github.com/bane-labs/zk-dkg/helper"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

/**
 * Function: PrepareEncryptedKeyShares
 * @Description: encrypt a batch of key shares and return related data
 * @param pubs: a set of public keys required for ecies encryption
 * @param fis: a set of key shares to be encrypted
 * @return fisBytes: a set of key shares, each in a byte array
 * @return fisInts: the key shares in integers
 * @return bigFis: the bls12381 commitments of the key shares
 * @return nonces: a set of salts
 * @return encryptedFis: a set of a encrypted key shares
 * @return rs: a set of the integer format of random number
 * @return bigRs: a set of the corresponding bls12381 commitment of random number
 */
func PrepareEncryptedKeyShares(pubs []*ecies.PublicKey, fis []fr_bls12381.Element) (fisBytes [][]byte, fisInts []big.Int, bigFis []bls12381.G1Affine, nonces [][]byte, encryptedFis [][]byte, rs []big.Int, bigRs []secp256k1.G1Affine) {
	amount := len(pubs)
	fisBytes = make([][]byte, amount)
	fisInts = make([]big.Int, amount)
	bigFis = make([]bls12381.G1Affine, amount)
	nonces = make([][]byte, amount)
	encryptedFis = make([][]byte, amount)
	rs = make([]big.Int, amount)
	bigRs = make([]secp256k1.G1Affine, amount)
	for i := 0; i < amount; i++ {
		fisBytes[i], fisInts[i], bigFis[i] = transformKeyShare(fis[i])
		nonces[i], encryptedFis[i], rs[i], bigRs[i] = encryptKeyShare(pubs[i], fisBytes[i])
	}
	return
}

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
func ComputeSingleKeyShareEncryptionAssignment(pubKey *ecies.PublicKey, r big.Int, bigR secp256k1.G1Affine, fiBytes []byte, fiInt big.Int, bigFi bls12381.G1Affine, encryptedFi []byte, nonce []byte) (*ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], []byte) {
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
	// Compute hash
	sumHash := computeSumHash(pub, bigR, bigFi, encryptedFi, nonce)
	rawSumHash := make([]frontend.Variable, len(sumHash))
	for i := 0; i < len(sumHash); i++ {
		rawSumHash[i] = sumHash[i]
	}
	// Compute assignment
	assignment := &ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
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
	return assignment, sumHash
}

// ComputeMultipleKeyShareEncryptionAssignment loops and computes an assignment array for several key share
// encryption jobs. And it also returns the sum hash of all assignments.
func ComputeMultipleKeyShareEncryptionAssignment(batch int, pubKey []*ecies.PublicKey, rs []big.Int, bigRs []secp256k1.G1Affine, fisBytes [][]byte, fisInts []big.Int, bigFis []bls12381.G1Affine, encryptedFis [][]byte, nonces [][]byte) ([]*ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], []byte) {
	assignments := make([]*ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], batch)
	hashes := make([][]byte, batch)
	for i := 0; i < batch; i++ {
		assignments[i], hashes[i] = ComputeSingleKeyShareEncryptionAssignment(pubKey[i], rs[i], bigRs[i], fisBytes[i], fisInts[i], bigFis[i], encryptedFis[i], nonces[i])
	}
	// Compute sum hash
	data := make([]byte, 0)
	for i := 0; i < batch; i++ {
		data = append(data, hashes[i]...)
	}
	return assignments, helper.GetHash(data)
}

// ComputeRecursionEncryptionAssignment computes the assignment for verification recursion.
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

// ComputeInnerProof computes the inner proof for a single key share encryption.
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

// ComputeInnerProofs computes the inner proofs for a batch of key share encryptions.
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

// GetSingleKeyShareEncryptionCircuit returns a circuit for a single key share encryption.
func GetSingleKeyShareEncryptionCircuit(fiBytes []byte, encryptedFi []byte) *ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr] {
	circuit := &ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		PlainChunks:  make([]frontend.Variable, len(fiBytes)),
		CipherChunks: make([]frontend.Variable, len(encryptedFi)),
		PubInputHash: make([]frontend.Variable, 32),
	}
	return circuit
}

// GetRecursionEncryptionCircuit returns a circuit for proving the verification of a batch of key share encryptions.
func GetRecursionEncryptionCircuit(batch int, innerCcss []constraint.ConstraintSystem, innerVKs []*groth16.VerifyingKey) *RecursionEncryptionWrapper[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl] {
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
