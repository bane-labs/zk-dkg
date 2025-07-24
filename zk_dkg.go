package zkdkg

import (
	"fmt"
	"math/big"
	"strconv"

	"github.com/bane-labs/zk-dkg/circuit"
	"github.com/bane-labs/zk-dkg/helper"
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

/**
 * Function: ProveMultipleKeyShareEncryption
 * @Description: generate a zk proof of a key share batch generating process
 * @param ccs: compiled circuit constraint system
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
func ProveMultipleKeyShareEncryption(outerCCS constraint.ConstraintSystem, outerProvingKey plonk.ProvingKey, vks []plonk.VerifyingKey, innerCCS constraint.ConstraintSystem, innerPK plonk.ProvingKey, innerVK plonk.VerifyingKey, pubKey []*ecies.PublicKey, rs []*big.Int, bigRs []*secp256k1.G1Affine, fisInts []*big.Int, bigFis []*bls12381.G1Affine, encryptedFis [][]byte, nonces [][]byte) (plonk.Proof, witness.Witness, error) {
	// Check batch, pk and vk
	batch := len(pubKey)
	supportedBatches := []int{1, 2, 7}
	if len(vks) != len(supportedBatches) {
		return nil, nil, fmt.Errorf("invalid vk array")
	}
	vkIndex := -1
	for i := 0; i < len(supportedBatches); i++ {
		if supportedBatches[i] == batch {
			vkIndex = i
			break
		}
	}
	if vkIndex == -1 {
		return nil, nil, fmt.Errorf("unsupported batch size: %d", batch)
	}
	// Compute assignment and proof
	innerAssignment, sumHash, err := circuit.ComputeMultipleKeyShareEncryptionAssignment(batch, pubKey, rs, bigRs, fisInts, bigFis, encryptedFis, nonces)
	if err != nil {
		return nil, nil, err
	}
	rawSumHash := make([]frontend.Variable, len(sumHash))
	for i := 0; i < len(sumHash); i++ {
		rawSumHash[i] = sumHash[i]
	}
	outerAssignment, err := circuit.ComputeRecursionEncryptionAssignment(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), vkIndex, vks, innerCCS, innerPK, innerVK, innerAssignment, rawSumHash)
	if err != nil {
		return nil, nil, err
	}
	proof, witness, err := helper.ComputeProof(outerCCS, outerProvingKey, outerAssignment)
	if err != nil {
		return nil, nil, err
	}
	var temp = fmt.Sprintf("\"%d\",", vkIndex)
	for k := 0; k < len(sumHash); k++ {
		temp = temp + "\"" + strconv.Itoa(int(sumHash[k])) + "\"" + ","
	}
	fmt.Println("public input is", temp)
	return proof, witness, nil
}
