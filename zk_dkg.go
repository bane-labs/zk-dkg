package zkdkg

import (
	"math/big"

	"github.com/bane-labs/zk-dkg/circuit"
	"github.com/bane-labs/zk-dkg/helper"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

/**
 * Function: ProveSingleKeyShareEncryption
 * @Description: generate a zk proof of a key share generating process
 * @param phase1Path: phase1 file path required for proof calculation
 * @param phase2Path: phase2 file path required for proof calculation
 * @param pubKey: public key used for key share encryption
 * @param r: the integer format of random number
 * @param bigR: the corresponding elliptic curve point of random number
 * @param fiBytes: the key share in a byte array
 * @param fiInt: the integer format of the key share
 * @param bigFi: the bls12381 commitment of the key share
 * @param encryptedFi: the encrypted key share
 * @param nonce: salt
 * @return vk: verification key of zk proof
 * @return proof: zk proof
 * @return witness: witness of zk proof
 * @return err:
 */
func ProveSingleKeyShareEncryption(phase1Path string, phase2Path string, pubKey *ecies.PublicKey, r big.Int, bigR secp256k1.G1Affine, fiBytes []byte, fiInt big.Int, bigFi bls12381.G1Affine, encryptedFi []byte, nonce []byte) (vk groth16.VerifyingKey, proof *groth16.Proof, witness witness.Witness, err error) {
	css, _, assignment, err := circuit.ComputeSingleKeyShareEncryptionAssignment(pubKey, r, bigR, fiBytes, fiInt, bigFi, encryptedFi, nonce)
	if err != nil {
		return groth16.VerifyingKey{}, nil, nil, err
	}
	_, vk, proof, witness, err = helper.ComputeProof(phase1Path, phase2Path, css, &assignment)
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
 * Function: ProveMultipleKeyShareEncryption
 * @Description: generate a zk proof of a key share batch generating process
 * @param phase1Path: phase1 file path required for proof calculation
 * @param phase2Path: phase2 file path required for proof calculation
 * @param pubKey: a set of public keys used for key share encryption
 * @param rs: a set of the integer format of random numbers
 * @param bigRs: a set of the corresponding elliptic curve point of random numbers
 * @param fisBytes: a set of the serialization format of the keys
 * @param fisInts: a set of the integer format of the keys
 * @param bigFis: a set of the corresponding elliptic curve points of the key
 * @param encryptedFis: a set of encrypted key shares
 * @param nonces: a set of salt
 * @return vk: verification key of zk proof
 * @return proof: zk proof
 * @return witness: witness of zk proof
 * @return err:
 */
func ProveMultipleKeyShareEncryption(phase1Path string, phase2Path string, pubKey []*ecies.PublicKey, rs []big.Int, bigRs []secp256k1.G1Affine, fisBytes [][]byte, fisInts []big.Int, bigFis []bls12381.G1Affine, encryptedFis [][]byte, nonces [][]byte) (vk groth16.VerifyingKey, proof *groth16.Proof, witness witness.Witness, err error) {
	css, _, assignment, err := circuit.ComputeMultipleKeyShareEncryptionAssignment(len(pubKey), pubKey, rs, bigRs, fisBytes, fisInts, bigFis, encryptedFis, nonces)
	if err != nil {
		return groth16.VerifyingKey{}, nil, nil, err
	}
	_, vk, proof, witness, err = helper.ComputeProof(phase1Path, phase2Path, css, assignment)
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


func ProveMultipleKeyShareEncryptionAggregated(phase1Path string, phase2Path string, pubKey []*ecies.PublicKey, rs []big.Int, bigRs []secp256k1.G1Affine, fisBytes [][]byte, fisInts []big.Int, bigFis []bls12381.G1Affine, encryptedFis [][]byte, nonces [][]byte) (vk groth16.VerifyingKey, proof *groth16.Proof, witness witness.Witness, err error) {
	css, _, assignment, err := circuit.ComputeMultipleKeyShareEncryptionAssignmentAggregated(phase1Path, phase2Path, len(pubKey), pubKey, rs, bigRs, fisBytes, fisInts, bigFis, encryptedFis, nonces)
	if err != nil {
		return groth16.VerifyingKey{}, nil, nil, err
	}
	_, vk, proof, witness, err = helper.ComputeProof(phase1Path, phase2Path, css, assignment)
	if err != nil {
		return groth16.VerifyingKey{}, nil, nil, err
	}
	return
}