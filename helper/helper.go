package helper

import (
	"crypto/sha256"
	"math/big"
	"os"

	"github.com/bane-labs/zk-dkg/mpc"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/backend/solidity"
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
func ComputeProof(ccs constraint.ConstraintSystem, pk *groth16.ProvingKey, assignment frontend.Circuit) (*groth16.Proof, witness.Witness, error) {
	// Compute witness
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, err
	}
	// Compute proof
	proof, err := groth16.Prove(ccs.(*cs.R1CS), pk, witness, backend.WithProverHashToFieldFunction(sha256.New()))
	if err != nil {
		return nil, nil, err
	}
	return proof, witness, nil
}

/**
 * Function: GetInitParamsFromExistedMPCSetUp
 * @Description: get proving key and verification key required for zk proof calculation from the existing MPC file
 * @param ccs: circuit constraints
 * @param srsPath: phase1 SRS file path required for proof calculation
 * @param phase2Path: phase2 file path required for proof calculation
 * @return pk: proving key
 * @return vk: verification key
 * @return err: error
 */
func GetInitParamsFromExistedMPCSetUp(ccs constraint.ConstraintSystem, srsPath string, phase2Path string) (*groth16.ProvingKey, *groth16.VerifyingKey, error) {
	// Get phase1 data
	srs, err := mpc.ReadSrsCommonsFromFile(srsPath)
	if err != nil {
		return nil, nil, err
	}
	// Get phase1.5 data
	r1cs := ccs.(*cs.R1CS)
	p2 := new(mpcsetup.Phase2)
	evals := p2.Initialize(r1cs, srs)
	// Get phase2 data
	phase2, err := mpc.ReadPhase2FromFile(phase2Path)
	if err != nil {
		return nil, nil, err
	}
	// Generate proving and verifying keys
	pk, vk := phase2.Seal(srs, &evals, []byte("beacon Phase 2"))
	return pk.(*groth16.ProvingKey), vk.(*groth16.VerifyingKey), nil
}

/**
 * Function: ReadProvingKey
 * @Description: import proving key file
 * @param path: proving key file path
 */
func ReadProvingKey(path string) (*groth16.ProvingKey, error) {
	pk := new(groth16.ProvingKey)
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
 * Function: ExportProvingKey
 * @Description: export proving key file
 * @param pk: proving key
 */
func ExportProvingKey(pk *groth16.ProvingKey, path string) error {
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
 * Function: ReadVerifyingKey
 * @Description: import verifying key file
 * @param path: verifying key file path
 */
func ReadVerifyingKey(path string) (*groth16.VerifyingKey, error) {
	vk := new(groth16.VerifyingKey)
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
 * Function: ExportVerifyingKey
 * @Description: export verifying key file
 * @param vk: verifying key
 */
func ExportVerifyingKey(vk *groth16.VerifyingKey, path string) error {
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
 * Function: ReadCCS
 * @Description: import r1cs file
 * @param path: r1cs file path
 */
func ReadCCS(path string) (constraint.ConstraintSystem, error) {
	ccs := new(cs.R1CS)
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
 * Function: ExportCCS
 * @Description: export r1cs file
 * @param ccs: r1cs
 */
func ExportCCS(ccs constraint.ConstraintSystem, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	_, err = ccs.WriteTo(file)
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
func ExportContract(vk *groth16.VerifyingKey, path string) error {
	contract, err := os.Create(path)
	if err != nil {
		return err
	}
	return vk.ExportSolidity(contract, solidity.WithHashToFieldFunction(sha256.New()))
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
func GetContractInput(proof *groth16.Proof) ([8]*big.Int, []*big.Int, [2]*big.Int) {
	// Solidity contract inputs
	proofBytes := proof.MarshalSolidity()
	fpSize := 4 * 8
	var prf [8]*big.Int
	// proof.Ar, proof.Bs, proof.Krs
	for i := 0; i < 8; i++ {
		prf[i] = new(big.Int).SetBytes(proofBytes[fpSize*i : fpSize*(i+1)])
	}
	c := new(big.Int).SetBytes(proofBytes[fpSize*8 : fpSize*8+4])
	cmtCount := int(c.Int64())
	var cmts = make([]*big.Int, 2*cmtCount)
	// commitments
	for i := 0; i < 2*cmtCount; i++ {
		cmts[i] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+i*fpSize : fpSize*8+4+(i+1)*fpSize])
	}
	var cmtPok [2]*big.Int
	// commitmentPok
	cmtPok[0] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*cmtCount*fpSize : fpSize*8+4+2*cmtCount*fpSize+fpSize])
	cmtPok[1] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*cmtCount*fpSize+fpSize : fpSize*8+4+2*cmtCount*fpSize+2*fpSize])
	return prf, cmts, cmtPok
}
