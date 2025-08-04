package zkdkg

import (
	"math/big"

	"github.com/bane-labs/zk-dkg/circuit"
	"github.com/bane-labs/zk-dkg/helper"
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
 * @param sender: the sender address as identifier
 * @param pubKey: public key used for key share encryption
 * @param r: the integer format of random number
 * @param fiBytes: the key share in a byte array
 * @param fiInt: the integer format of the key share
 * @param encryptedFi: the encrypted key share
 * @param nonce: salt
 * @return proof: zk proof
 * @return witness: witness of zk proof
 * @return err:
 */
func ProveSingleKeyShareEncryption(css constraint.ConstraintSystem, provingKey *groth16.ProvingKey, sender [20]byte, pubKey *ecies.PublicKey, r *big.Int, fiInt *big.Int, encryptedFi []byte, nonce []byte) (*groth16.Proof, witness.Witness, error) {
	assignment, _, err := circuit.ComputeMultipleKeyShareEncryptionAssignment(sender, 1, []*ecies.PublicKey{pubKey}, []*big.Int{r}, []*big.Int{fiInt}, [][]byte{encryptedFi}, [][]byte{nonce})
	if err != nil {
		return nil, nil, err
	}
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
 * @param sender: the sender address as identifier
 * @param pubKey: a set of public keys used for key share encryption
 * @param rs: a set of the integer format of random numbers
 * @param fisBytes: a set of the serialization format of the keys
 * @param fisInts: a set of the integer format of the keys
 * @param encryptedFis: a set of encrypted key shares
 * @param nonces: a set of salt
 * @return proof: zk proof
 * @return witness: witness of zk proof
 * @return err:
 */
func ProveMultipleKeyShareEncryption(css constraint.ConstraintSystem, provingKey *groth16.ProvingKey, sender [20]byte, pubKey []*ecies.PublicKey, rs []*big.Int, fisInts []*big.Int, encryptedFis [][]byte, nonces [][]byte) (*groth16.Proof, witness.Witness, error) {
	assignment, _, err := circuit.ComputeMultipleKeyShareEncryptionAssignment(sender, len(pubKey), pubKey, rs, fisInts, encryptedFis, nonces)
	if err != nil {
		return nil, nil, err
	}
	proof, witness, err := helper.ComputeProof(css, provingKey, assignment)
	if err != nil {
		return nil, nil, err
	}
	return proof, witness, nil
}
