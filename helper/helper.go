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
 * @param phase1Path: phase1 file path required for proof calculation
 * @param phase2Path: phase2 file path required for proof calculation
 * @param css: circuit constraints
 * @param assignment: input data collection
 * @return pk: proving key
 * @return vk: verification key
 * @return proof: zk proof
 * @return witness: witness
 * @return err: error
 */
func ComputeProof(phase1Path string, phase2Path string, css constraint.ConstraintSystem, assignment frontend.Circuit) (pk groth16.ProvingKey, vk groth16.VerifyingKey, proof *groth16.Proof, witness witness.Witness, err error) {
	// Get proving and verifying keys
	pk, vk, _ = GetInitParamsFromExistedMPCSetUp(css, phase1Path, phase2Path)
	// Init setup
	err = groth16.Setup(css.(*cs.R1CS), &pk, &vk)
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, nil, nil, err
	}
	// Compute witness
	witness, err = frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, nil, nil, err
	}
	// Compute proof
	proof, err = groth16.Prove(css.(*cs.R1CS), &pk, witness, backend.WithProverHashToFieldFunction(sha256.New()))
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, nil, nil, err
	}
	return
}

/**
 * Function: GetInitParamsFromExistedMPCSetUp
 * @Description: get proving key and verification key required for zk proof calculation from the existing MPC file
 * @param ccs: circuit constraints
 * @param phase1Path: phase1 file path required for proof calculation
 * @param phase2Path: phase2 file path required for proof calculation
 * @return pk: proving key
 * @return vk: verification key
 * @return err: error
 */
func GetInitParamsFromExistedMPCSetUp(ccs constraint.ConstraintSystem, phase1Path string, phase2Path string) (pk groth16.ProvingKey, vk groth16.VerifyingKey, err error) {
	// Get phase1 data
	srs1, err := mpc.ReadPhase1FromFile(phase1Path)
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
	}
	// Get phase1.5 data
	var evals mpcsetup.Phase2Evaluations
	r1cs := ccs.(*cs.R1CS)
	_, evals = mpcsetup.InitPhase2(r1cs, &srs1)
	// Get phase2 data
	srs2, err := mpc.ReadPhase2FromFile(phase2Path)
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
	}
	// Generate proving and verifying keys
	pk, vk = mpcsetup.ExtractKeys(&srs1, &srs2, &evals, ccs.GetNbConstraints())
	return pk, vk, nil
}

/**
 * Function: ExportContract
 * @Description: export solidity file
 * @param vk: verifying key
 */
func ExportContract(vk groth16.VerifyingKey, path string) {
	contract, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	err = vk.ExportSolidity(contract, solidity.WithHashToFieldFunction(sha256.New()))
	if err != nil {
		panic(err)
	}
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
