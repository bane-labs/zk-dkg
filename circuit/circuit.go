package circuit

import (
	"fmt"
	"math/big"

	"github.com/bane-labs/zk-dkg/helper"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	plonk "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/commitments/kzg"
	"github.com/consensys/gnark/std/math/emulated"
	stdplonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

var hashDomain = "DKG_BATCH_HASH_V1"

/**
 * Function: PrepareEncryptedKeyShares
 * @Description: encrypt a batch of key shares and return related data
 * @param pubs: a set of public keys required for ecies encryption
 * @param fis: a set of key shares to be encrypted
 * @return fisInts: the key shares in integers
 * @return bigFis: the bls12381 commitments of the key shares
 * @return nonces: a set of salts
 * @return encryptedFis: a set of a encrypted key shares
 * @return rs: a set of the integer format of random number
 * @return bigRs: a set of the corresponding bls12381 commitment of random number
 * @return err: error
 */
func PrepareEncryptedKeyShares(pubs []*ecies.PublicKey, fis []*fr_bls12381.Element) ([]*big.Int, []*bls12381.G1Affine, [][]byte, [][]byte, []*big.Int, []*secp256k1.G1Affine, error) {
	amount := len(pubs)
	if amount != len(fis) {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("input array length mismatch")
	}
	fisBytes := make([][]byte, amount)
	fisInts := make([]*big.Int, amount)
	bigFis := make([]*bls12381.G1Affine, amount)
	nonces := make([][]byte, amount)
	encryptedFis := make([][]byte, amount)
	rs := make([]*big.Int, amount)
	bigRs := make([]*secp256k1.G1Affine, amount)
	var err error
	for i := 0; i < amount; i++ {
		if pubs[i] == nil || fis[i] == nil {
			return nil, nil, nil, nil, nil, nil, fmt.Errorf("invalid public key or key share at index %d", i)
		}
		fisBytes[i], fisInts[i], bigFis[i] = transformKeyShare(fis[i])
		nonces[i], encryptedFis[i], rs[i], bigRs[i], err = encryptKeyShare(pubs[i], fisBytes[i])
		if err != nil {
			return nil, nil, nil, nil, nil, nil, err
		}
	}
	return fisInts, bigFis, nonces, encryptedFis, rs, bigRs, nil
}

/**
 * Function: ComputeSingleKeyShareEncryptionAssignment
 * @Description: get input data collection for a zk proof calculation of a key share generating process
 * @param pubKey: public key used for key share encryption
 * @param r: the integer format of random number
 * @param bigR: the corresponding elliptic curve point of random number
 * @param fiInt: the integer format of the key share
 * @param bigFi: the bls12381 commitment of the key share
 * @param encryptedFi: the encrypted key
 * @param nonce: salt
 * @return css: circuit constraints
 * @return circuit: circuit
 * @return assignment: input data collection
 * @return err: error
 */
func ComputeSingleKeyShareEncryptionAssignment(pubKey *ecies.PublicKey, r *big.Int, bigR *secp256k1.G1Affine, fiInt *big.Int, bigFi *bls12381.G1Affine, encryptedFi []byte, nonce []byte) (ECIESParameters[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], []byte, error) {
	if pubKey == nil || r == nil || bigR == nil || fiInt == nil || bigFi == nil || len(encryptedFi) == 0 || len(nonce) == 0 {
		return ECIESParameters[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{}, nil, fmt.Errorf("invalid input data for assignment")
	}
	// Format data
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
	rPub := new(secp256k1.G1Affine).ScalarMultiplication(&pub, r)
	// Compute hash
	sumHash := computeSumHash(&pub, bigR, bigFi, encryptedFi, nonce)
	// Compute assignment
	assignment := ECIESParameters[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
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
		Iv:           nonceBytes,
		ChunkIndex:   2,
		CipherChunks: ciphertextBytes,

		SmallFi: emulated.ValueOf[emulated.BLS12381Fr](fiInt),
		Fi: sw_emulated.AffinePoint[emulated.BLS12381Fp]{
			X: emulated.ValueOf[emulated.BLS12381Fp](bigFi.X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](bigFi.Y),
		},
	}
	return assignment, sumHash, nil
}

// ComputeMultipleKeyShareEncryptionAssignment loops and computes an assignment array for several key share
// encryption jobs. And it also returns the sum hash of all assignments.
func ComputeMultipleKeyShareEncryptionAssignment(batch int, pubKey []*ecies.PublicKey, rs []*big.Int, bigRs []*secp256k1.G1Affine, fisInts []*big.Int, bigFis []*bls12381.G1Affine, encryptedFis [][]byte, nonces [][]byte) (*BatchEncryptionWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], []byte, error) {
	if len(pubKey) != batch || len(rs) != batch || len(bigRs) != batch || len(fisInts) != batch || len(bigFis) != batch || len(encryptedFis) != batch || len(nonces) != batch {
		return nil, nil, fmt.Errorf("input array length mismatch")
	}
	Parameters := make([]ECIESParameters[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], batch)
	innerhashes := make([][]byte, batch)
	var err error
	for i := 0; i < batch; i++ {
		Parameters[i], innerhashes[i], err = ComputeSingleKeyShareEncryptionAssignment(pubKey[i], rs[i], bigRs[i], fisInts[i], bigFis[i], encryptedFis[i], nonces[i])
		if err != nil {
			return nil, nil, err
		}
	}
	// Compute sum hash
	summary := make([]byte, 0)
	summary = append(summary, hashDomain...)
	summary = append(summary, byte(batch))
	for i := 0; i < batch; i++ {
		summary = append(summary, byte(i), byte(len(innerhashes[i])))
		summary = append(summary, innerhashes[i]...)
	}
	sumHash := helper.GetHash(summary)

	rawSumHash := make([]frontend.Variable, len(sumHash))
	for i := 0; i < len(sumHash); i++ {
		rawSumHash[i] = sumHash[i]
	}
	assignments := &BatchEncryptionWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		Parameters: Parameters,
		SumHash:    rawSumHash,
	}
	return assignments, sumHash, nil
}

// ComputeRecursionEncryptionAssignment computes the assignment for verification recursion.
func ComputeRecursionEncryptionAssignment(field, outer *big.Int, vkIndex int, vks []native_plonk.VerifyingKey, innerCcs constraint.ConstraintSystem, innerPK native_plonk.ProvingKey, innerVK native_plonk.VerifyingKey, innerAssignments *BatchEncryptionWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], sumHash []frontend.Variable) (*RecursionEncryptionWrapper[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl], error) {
	innerProofs, innerWitness, err := ComputeInnerProof(field, outer, innerCcs, innerPK, innerVK, innerAssignments)
	if err != nil {
		return nil, err
	}
	circuitWitness, err := stdplonk.ValueOfWitness[sw_bn254.ScalarField](innerWitness)
	if err != nil {
		return nil, err
	}
	circuitProof, err := stdplonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerProofs)
	if err != nil {
		return nil, err
	}

	circuitVks := make([]stdplonk.CircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine], len(vks))
	var baseVk stdplonk.BaseVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]
	for i, vk := range vks {
		pvk, err := stdplonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](vk)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			baseVk = pvk.BaseVerifyingKey
		}
		circuitVks[i] = pvk.CircuitVerifyingKey
	}

	outerAssignment := &RecursionEncryptionWrapper[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness:         [32]emulated.Element[sw_bn254.ScalarField](circuitWitness.Public),
		Proof:                circuitProof,
		SumHash:              [32]frontend.Variable(sumHash),
		VerifyingKeyIndex:    vkIndex,
		BaseVerifyingKey:     baseVk,
		CircuitVerifyingKeys: circuitVks,
	}
	return outerAssignment, nil
}

// ComputeInnerProof computes the inner proof for a single key share encryption.
func ComputeInnerProof(field, outer *big.Int, innerCcs constraint.ConstraintSystem, innerPK native_plonk.ProvingKey, innerVK native_plonk.VerifyingKey, innerAssignment *BatchEncryptionWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]) (*plonk.Proof, witness.Witness, error) {
	r1cs := innerCcs.(*cs.SparseR1CS)
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	if err != nil {
		return nil, nil, err
	}
	innerPubWitness, err := innerWitness.Public()
	if err != nil {
		return nil, nil, err
	}
	p := innerPK.(*plonk.ProvingKey)
	v := innerVK.(*plonk.VerifyingKey)
	innerProof, err := plonk.Prove(r1cs, p, innerWitness, stdplonk.GetNativeProverOptions(outer, field))
	if err != nil {
		return nil, nil, err
	}
	err = plonk.Verify(innerProof, v, innerPubWitness.Vector().(fr_bn254.Vector), stdplonk.GetNativeVerifierOptions(outer, field))
	if err != nil {
		return nil, nil, err
	}
	return innerProof, innerPubWitness, nil
}

// GetBatchEncryptionCircuit returns a circuit for a single key share encryption.
func GetBatchEncryptionCircuit(encryptedFis [][]byte) *BatchEncryptionWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr] {
	batch := len(encryptedFis)
	circuit := &BatchEncryptionWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		Parameters: make([]ECIESParameters[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], batch),
		SumHash:    make([]frontend.Variable, 32),
	}
	for i := 0; i < batch; i++ {
		circuit.Parameters[i].CipherChunks = make([]frontend.Variable, len(encryptedFis[i]))
	}
	return circuit
}

// GetRecursionEncryptionCircuit returns a circuit for proving the verification of a batch of key share encryptions.
func GetRecursionEncryptionCircuit(nbPublic int, nbCommitments int, vks []native_plonk.VerifyingKey) (*RecursionEncryptionWrapper[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl], error) {
	circuitVks := make([]stdplonk.CircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine], len(vks))
	var baseVk stdplonk.BaseVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]
	for i, vk := range vks {
		pvk, err := stdplonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](vk)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			baseVk = pvk.BaseVerifyingKey
		}
		circuitVks[i] = pvk.CircuitVerifyingKey
	}

	circuitWitness := stdplonk.Witness[sw_bn254.ScalarField]{
		Public: make([]emulated.Element[sw_bn254.ScalarField], nbPublic),
	}
	circuitProof := stdplonk.Proof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]{
		BatchedProof: kzg.BatchOpeningProof[sw_bn254.ScalarField, sw_bn254.G1Affine]{
			ClaimedValues: make([]emulated.Element[sw_bn254.ScalarField], 6+nbCommitments),
		},
		Bsb22Commitments: make([]kzg.Commitment[sw_bn254.G1Affine], nbCommitments),
	}
	return &RecursionEncryptionWrapper[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness:         [32]emulated.Element[sw_bn254.ScalarField](circuitWitness.Public),
		BaseVerifyingKey:     baseVk,
		CircuitVerifyingKeys: circuitVks,
		Proof:                circuitProof,
	}, nil
}
