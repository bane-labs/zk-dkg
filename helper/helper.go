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
 * @param css: circuit constraints
 * @param pk: proving key
 * @param assignment: input data collection
 * @return proof: zk proof
 * @return witness: witness
 * @return err: error
 */
func ComputeProof(css constraint.ConstraintSystem, pk *groth16.ProvingKey, assignment frontend.Circuit) (*groth16.Proof, witness.Witness, error) {
	// Compute witness
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, err
	}
	// Compute proof
	proof, err := groth16.Prove(css.(*cs.R1CS), pk, witness, backend.WithProverHashToFieldFunction(sha256.New()))
	if err != nil {
		return nil, nil, err
	}
	return proof, witness, nil
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
func GetInitParamsFromExistedMPCSetUp(ccs constraint.ConstraintSystem, phase1Path string, phase2Path string) (*groth16.ProvingKey, *groth16.VerifyingKey, error) {
	// Get phase1 data
	srs, err := mpc.ReadSrsCommonsFromFile(phase1Path)
	if err != nil {
		return nil, nil, err
	}
	// Get phase1.5 data
	r1cs := ccs.(*cs.R1CS)
	p2 := new(mpcsetup.Phase2)
	evals := p2.Initialize(r1cs, &srs)
	// Get phase2 data
	phase2, err := mpc.ReadPhase2FromFile(phase2Path)
	if err != nil {
		return nil, nil, err
	}
	// Generate proving and verifying keys
	pk, vk := phase2.Seal(&srs, &evals, []byte("beacon Phase 2"))
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
func ExportProvingKey(pk *groth16.ProvingKey, path string) {
	file, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	_, err = pk.WriteTo(file)
	if err != nil {
		panic(err)
	}
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
func ExportVerifyingKey(vk *groth16.VerifyingKey, path string) {
	file, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	_, err = vk.WriteTo(file)
	if err != nil {
		panic(err)
	}
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
func ExportCSS(css constraint.ConstraintSystem, path string) {
	file, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	_, err = css.WriteTo(file)
	if err != nil {
		panic(err)
	}
}

/**
 * Function: ExportContract
 * @Description: export solidity file
 * @param vk: verifying key
 */
func ExportContract(vk *groth16.VerifyingKey, path string) {
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
