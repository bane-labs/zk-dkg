package helper

import (
	"crypto/sha256"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
)

/**
 * Function: ComputeProof
 * @Description: a general zk proof calculation method
 * @param ccs: circuit constraints
 * @param pk: proving key
 * @param assignment: input data collection
 * @return proof: zk proof
 * @return witness: witness
 * @return err: error
 */
func ComputeProof(ccs constraint.ConstraintSystem, pk plonk.ProvingKey, assignment frontend.Circuit) (plonk.Proof, witness.Witness, error) {
	// Compute witness
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, err
	}
	// Compute proof
	proof, err := plonk.Prove(ccs, pk, witness) // no need to set hashToField Option. If this option is set, then the verification outside should have the corresponding option.
	if err != nil {
		return nil, nil, err
	}
	return proof, witness, nil
}

/**
 * Function: ReadPlonkProvingKey
 * @Description: import proving key file
 * @param path: proving key file path
 */
func ReadPlonkProvingKey(path string, curveID ecc.ID) (plonk.ProvingKey, error) {
	pk := plonk.NewProvingKey(curveID)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	_, err = pk.ReadFrom(file)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

/**
 * Function: ReadPlonkVerifyingKey
 * @Description: import verifying key file
 * @param path: verifying key file path
 * @return vk: verifying key
 * @return err: error
 */
func ReadPlonkVerifyingKey(path string, curveID ecc.ID) (plonk.VerifyingKey, error) {
	vk := plonk.NewVerifyingKey(curveID)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	_, err = vk.ReadFrom(file)
	if err != nil {
		return nil, err
	}
	return vk, nil
}

/**
 * Function: ReadCCS
 * @Description: import r1cs file
 * @param path: r1cs file path
 */
func ReadCCS(path string) (constraint.ConstraintSystem, error) {
	ccs := new(cs.SparseR1CS)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	_, err = ccs.ReadFrom(file)
	if err != nil {
		return nil, err
	}
	return ccs, nil
}

/**
 * Function: GetHash
 * @Description: get data hash
 * @param data: data
 * @return [32]byte: hash
 */
func GetHash(data []byte) [32]byte {
	return sha256.Sum256(data)
}

/**
 * Function: GetContractInput
 * @Description: get the data submitted to the chain
 * @param proof: zk proof
 * @return []*big.Int: data submitted to the chain
 */
func GetContractInput(proof plonk.Proof) []byte {
	plonk_proof := proof.(*plonk_bn254.Proof)
	input := plonk_proof.MarshalSolidity()
	return input
}
