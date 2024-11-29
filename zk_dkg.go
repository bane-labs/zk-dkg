package zkdkg

import (
	"crypto/sha256"
	"math/big"

	"github.com/bane-labs/zk-dkg/circuit"
	"github.com/bane-labs/zk-dkg/mpc"
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark/backend"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

/**
 * Function:GenerateProof
 * @Description: generate a zk proof of a key fragment generating process
 * @param phase1Path: phase1 file path required for proof calculation
 * @param phase2Path: phase2 file path required for proof calculation
 * @param pubKey: public key required for asymmetric encryption
 * @param rs: the integer format of random number
 * @param rb: the corresponding elliptic curve point of random number
 * @param fiBytes: the serialization format of the key
 * @param sfi: the integer format of the key
 * @param bfi: the corresponding elliptic curve point of the key
 * @param ctt: a encrypted key fragments
 * @param nonce: salt
 * @return vk: verification key of zk proof
 * @return proof: zk proof
 * @return witness: witness of zk proof
 * @return err:
 */
func GenerateProof(phase1Path string, phase2Path string, pubKey ecies.PublicKey, rs big.Int, rb secp256k1.G1Affine, fiBytes []byte, sfi big.Int, bfi bls12381.G1Affine, ctt []byte, nonce []byte) (vk groth16.VerifyingKey, proof *groth16.Proof, witness witness.Witness, err error) {
	css, _, assignment, err := circuit.ComputingAssignment(pubKey, rs, rb, fiBytes, sfi, bfi, ctt, nonce)
	if err != nil {
		return groth16.VerifyingKey{}, nil, nil, err
	}
	_, vk, proof, witness, err = ComputingProof(phase1Path, phase2Path, css, &assignment)
	if err != nil {
		return groth16.VerifyingKey{}, nil, nil, err
	}
	/*
		schema, _ := frontend.NewSchema(&circuit)
		public, err := witness.Public()
		if err != nil {
			return groth16.VerifyingKey{}, nil, nil, err
		}
		ret, _ := public.ToJSON(schema)
		var b bytes.Buffer
		json.Indent(&b, ret, "", "\t")
		println(b.String())*/
	return
}

/**
 * Function:BatchGenerateProof
 * @Description: generate a zk proof of a key fragment batch generating process
 * @param phase1Path: phase1 file path required for proof calculation
 * @param phase2Path: phase2 file path required for proof calculation
 * @param pubKey: a set of public key required for asymmetric encryption
 * @param rs: a set of the integer format of random number
 * @param rb: a set of the corresponding elliptic curve point of random number
 * @param fiBytes: a set of the serialization format of the key
 * @param sfi: a set of the integer format of the key
 * @param bfi: a set of the corresponding elliptic curve point of the key
 * @param ctt: a set of a encrypted key fragments
 * @param nonce: a set of salt
 * @return vk: verification key of zk proof
 * @return proof: zk proof
 * @return witness: witness of zk proof
 * @return err:
 */
func BatchGenerateProof(phase1Path string, phase2Path string, pubKey []ecies.PublicKey, rs []big.Int, rb []secp256k1.G1Affine, fiBytes [][]byte, sfi []big.Int, bfi []bls12381.G1Affine, ctt [][]byte, nonce [][]byte) (vk groth16.VerifyingKey, proof *groth16.Proof, witness witness.Witness, err error) {
	css, _, assignment, err := circuit.BatchComputingAssignment(len(pubKey), pubKey, rs, rb, fiBytes, sfi, bfi, ctt, nonce)
	if err != nil {
		return groth16.VerifyingKey{}, nil, nil, err
	}
	_, vk, proof, witness, err = ComputingProof(phase1Path, phase2Path, css, assignment)
	if err != nil {
		return groth16.VerifyingKey{}, nil, nil, err
	}

	/*	schema, _ := frontend.NewSchema(&circuit)
		public, err := witness.Public()
		if err != nil {
			return groth16.VerifyingKey{}, nil, nil, err
		}
		ret, _ := public.ToJSON(schema)
		var b bytes.Buffer
		json.Indent(&b, ret, "", "\t")
		println(b.String())*/
	return
}

/**
 * Function:ComputingProof
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
func ComputingProof(phase1Path string, phase2Path string, css constraint.ConstraintSystem, assignment frontend.Circuit) (pk groth16.ProvingKey, vk groth16.VerifyingKey, proof *groth16.Proof, witness witness.Witness, err error) {
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
 * Function:GetInitParamsFromExistedMPCSetUp
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
