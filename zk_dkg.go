package zkdkg

import (
	"math/big"

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
func ProveSingleKeyShareEncryption(css constraint.ConstraintSystem, provingKey *groth16.ProvingKey, pubKey *ecies.PublicKey, r big.Int, bigR secp256k1.G1Affine, fiBytes []byte, fiInt big.Int, bigFi bls12381.G1Affine, encryptedFi []byte, nonce []byte) (*groth16.Proof, witness.Witness, error) {
	assignment := circuit.ComputeSingleKeyShareEncryptionAssignment(pubKey, r, bigR, fiBytes, fiInt, bigFi, encryptedFi, nonce)
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
func ProveMultipleKeyShareEncryption(css constraint.ConstraintSystem, provingKey *groth16.ProvingKey, pubKey []*ecies.PublicKey, rs []big.Int, bigRs []secp256k1.G1Affine, fisBytes [][]byte, fisInts []big.Int, bigFis []bls12381.G1Affine, encryptedFis [][]byte, nonces [][]byte) (*groth16.Proof, witness.Witness, error) {
	assignment := circuit.ComputeMultipleKeyShareEncryptionAssignment(len(pubKey), pubKey, rs, bigRs, fisBytes, fisInts, bigFis, encryptedFis, nonces)
	proof, witness, err := helper.ComputeProof(css, provingKey, assignment)
	if err != nil {
		return nil, nil, err
	}
	return proof, witness, nil
}
