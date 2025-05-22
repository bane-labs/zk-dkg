package zkdkg

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"

	"github.com/bane-labs/zk-dkg/circuit"
	"github.com/bane-labs/zk-dkg/helper"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

/**
 * Function: ProveSingleKeyShareEncryption
 * @Description: generate a zk proof of a key share generating process
 * @param css: compiled circuit constraint system
 * @param provingKey: proving key used for proof encryption
 * @param pubKey: public key used for key share encryption
 * @param r: the integer format of random number
 * @param bigR: the corresponding elliptic curve point of random number
 * @param fiBytes: the key share in a byte array
 * @param fiInt: the integer format of the key share
 * @param bigFi: the bls12381 commitment of the key share
 * @param encryptedFi: the encrypted key share
 * @param nonce: salt
 * @return proof: zk proof
 * @return witness: witness of zk proof
 * @return err:
 */
func ProveSingleKeyShareEncryption(css constraint.ConstraintSystem, provingKey plonk.ProvingKey, pubKey *ecies.PublicKey, r *big.Int, bigR *secp256k1.G1Affine, fiBytes []byte, fiInt *big.Int, bigFi *bls12381.G1Affine, encryptedFi []byte, nonce []byte) (plonk.Proof, witness.Witness, error) {
	assignment, _ := circuit.ComputeSingleKeyShareEncryptionAssignment(pubKey, r, bigR, fiBytes, fiInt, bigFi, encryptedFi, nonce)
	proof, witness, err := helper.ComputeProof(css, provingKey, assignment)
	if err != nil {
		return nil, nil, err
	}
	return proof, witness, nil
}

/**
 * Function: ProveMultipleKeyShareEncryption
 * @Description: generate a zk proof of a key share batch generating process
 * @param css: compiled circuit constraint system
 * @param provingKey: proving key used for proof encryption
 * @param pubKey: a set of public keys used for key share encryption
 * @param rs: a set of the integer format of random numbers
 * @param bigRs: a set of the corresponding elliptic curve point of random numbers
 * @param fisBytes: a set of the serialization format of the keys
 * @param fisInts: a set of the integer format of the keys
 * @param bigFis: a set of the corresponding elliptic curve points of the key
 * @param encryptedFis: a set of encrypted key shares
 * @param nonces: a set of salt
 * @return proof: zk proof
 * @return witness: witness of zk proof
 * @return err:
 */
func ProveMultipleKeyShareEncryption(outerCss constraint.ConstraintSystem, outerProvingKey plonk.ProvingKey, innerCcss []constraint.ConstraintSystem, innerPKs []*groth16.ProvingKey, innerVKs []*groth16.VerifyingKey, pubKey []*ecies.PublicKey, rs []*big.Int, bigRs []*secp256k1.G1Affine, fisBytes [][]byte, fisInts []*big.Int, bigFis []*bls12381.G1Affine, encryptedFis [][]byte, nonces [][]byte) (plonk.Proof, witness.Witness, error) {
	batch := len(innerCcss)
	innerAssignments, sumHash := circuit.ComputeMultipleKeyShareEncryptionAssignment(batch, pubKey, rs, bigRs, fisBytes, fisInts, bigFis, encryptedFis, nonces)
	rawSumHash := make([]frontend.Variable, len(sumHash))
	for i := 0; i < len(sumHash); i++ {
		rawSumHash[i] = sumHash[i]
	}
	outerAssignment, err := circuit.ComputeRecursionEncryptionAssignment(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), batch, innerCcss, innerPKs, innerVKs, innerAssignments, rawSumHash)
	if err != nil {
		return nil, nil, err
	}
	proof, witness, err := helper.ComputeProof(outerCss, outerProvingKey, outerAssignment)
	if err != nil {
		return nil, nil, err
	}
	return proof, witness, nil
}
