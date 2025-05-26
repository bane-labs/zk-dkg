package helper

import (
	"crypto/sha256"
	"os"

	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"

	"github.com/bane-labs/zk-dkg/mpc"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
)

/**
 * Function: ComputeProof
 * @Description: a general zk proof calculation method
 * @param css: circuit constraints
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
	proof, err := plonk.Prove(ccs.(*cs.R1CS), pk, witness, backend.WithProverHashToFieldFunction(sha256.New()))
	if err != nil {
		return nil, nil, err
	}
	return proof, witness, nil
}

/**
 * Function: GetKeysFromExistedPlonkSetUp
 * @Description: get proving key and verification key required for zk proof calculation from the existing MPC file
 * @param ccs: circuit constraints
 * @param srsPath: phase1 SRS file path required for proof calculation
 * @return pk: proving key
 * @return vk: verification key
 * @return err: error
 */
func GetKeysFromExistedPlonkSetUp(ccs constraint.ConstraintSystem, srsPath string) (*plonk_bn254.ProvingKey, *plonk_bn254.VerifyingKey, error) {
	r1CS := ccs.(*cs.SparseR1CS)
	srsSize, lagrange := plonk.SRSSize(r1CS)
	srs, err := mpc.SealPlonkSRS(srsPath, srsSize)
	if err != nil {
		return nil, nil, err
	}
	srsLagrange := &kzg_bn254.SRS{Vk: srs.Vk}
	srsLagrange.Pk.G1, err = kzg_bn254.ToLagrangeG1(srs.Pk.G1[:lagrange])
	if err != nil {
		return nil, nil, err
	}
	p1, v1, err := plonk.Setup(r1CS, srs, srsLagrange)
	if err != nil {
		return nil, nil, err
	}
	pk := p1.(*plonk_bn254.ProvingKey)
	vk := v1.(*plonk_bn254.VerifyingKey)
	return pk, vk, nil
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
 * Function: ExportOuterProvingKey
 * @Description: export proving key file
 * @param pk: proving key
 * @param path: proving key file path
 */
func ExportPlonkProvingKey(pk plonk.ProvingKey, path string) error {
	//key := pk.(*plonk_bn254.ProvingKey)
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	_, err = pk.WriteTo(file)
	if err != nil {
		return err
	}
	return nil
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
 * Function: ExportPlonkVerifyingKey
 * @Description: export verifying key file
 * @param vk: verifying key
 * @param path: verifying key file path
 */
func ExportPlonkVerifyingKey(vk plonk.VerifyingKey, path string) error {
	//key := vk.(*plonk_bn254.VerifyingKey)
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	_, err = vk.WriteTo(file)
	if err != nil {
		return err
	}
	return nil
}

/**
 * Function: ReadCSS
 * @Description: import r1cs file
 * @param path: r1cs file path
 */
func ReadCSS(path string) (constraint.ConstraintSystem, error) {
	css := new(cs.R1CS)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	_, err = css.ReadFrom(file)
	if err != nil {
		return nil, err
	}
	return css, nil
}

/**
 * Function: ExportCSS
 * @Description: export r1cs file
 * @param css: r1cs
 */
func ExportCSS(css constraint.ConstraintSystem, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	_, err = css.WriteTo(file)
	if err != nil {
		return err
	}
	return nil
}

/**
 * Function: ExportContract
 * @Description: export solidity file
 * @param vk: verifying key
 */
func ExportContract(vk plonk.VerifyingKey, path string) error {
	contract, err := os.Create(path)
	if err != nil {
		return err
	}
	defer contract.Close()
	VK := vk.(*plonk_bn254.VerifyingKey)
	//err = VK.ExportSolidity(contract, solidity.WithHashToFieldFunction(sha256.New()))
	err = VK.ExportSolidity(contract)
	if err != nil {
		return err
	}
	return nil
}

/**
 * Function: GetHash
 * @Description: get data hash
 * @param data: data
 * @return []byte: hash
 */
func GetHash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
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
