package helper

import (
	"crypto/sha256"
	"math/big"
	"os"

	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/solidity"
	"golang.org/x/crypto/sha3"
)

/**
 * Function:ExportContract
 * @Description: export solidity file
 * @param vk: verifying key
 */
func ExportContract(vk groth16.VerifyingKey) {
	contract, err := os.Create("verify.sol")
	if err != nil {
		panic(err)
	}
	err = vk.ExportSolidity(contract, solidity.WithHashToFieldFunction(sha256.New()))
	if err != nil {
		panic(err)
	}
}

/**
 * Function:GetHash
 * @Description: get data hash
 * @param data: data
 * @return []byte: hash
 */
func GetHash(data []byte) []byte {
	hashBuilder := sha3.New256()
	hashBuilder.Write(data)
	return hashBuilder.Sum(nil)
}

/**
 * Function:GetOutputData
 * @Description: get the data submitted to the chain
 * @param proof: zk proof
 * @return Output: data submitted to the chain
 */
func GetOutputData(proof *groth16.Proof) Output {
	// Solidity contract inputs
	var output Output
	proofBytes := proof.MarshalSolidity()
	fpSize := 4 * 8
	var prf [8]*big.Int
	// proof.Ar, proof.Bs, proof.Krs
	for i := 0; i < 8; i++ {
		prf[i] = new(big.Int).SetBytes(proofBytes[fpSize*i : fpSize*(i+1)])
	}
	output.proof = prf[:]
	c := new(big.Int).SetBytes(proofBytes[fpSize*8 : fpSize*8+4])
	cmtCount := int(c.Int64())
	var cmts = make([]big.Int, 2*cmtCount)
	// commitments
	for i := 0; i < 2*cmtCount; i++ {
		cmts[i].SetBytes(proofBytes[fpSize*8+4+i*fpSize : fpSize*8+4+(i+1)*fpSize])
	}
	output.commitments = cmts
	var cmtPok [2]*big.Int
	// commitmentPok
	cmtPok[0] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*cmtCount*fpSize : fpSize*8+4+2*cmtCount*fpSize+fpSize])
	cmtPok[1] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*cmtCount*fpSize+fpSize : fpSize*8+4+2*cmtCount*fpSize+2*fpSize])
	output.commitmentPok = cmtPok[:]
	return output
}

type Output struct {
	proof         []*big.Int
	commitments   []big.Int
	commitmentPok []*big.Int
}

func (output *Output) Printf() {
	// proof.Ar, proof.Bs, proof.Krs
	println("printf proof:")
	for i := 0; i < 8; i++ {
		println("proof:" + output.proof[i].String())
	}
	// commitments
	println("printf commitments")
	for i := 0; i < len(output.commitments); i++ {
		println(output.commitments[i].String())
	}
	// commitmentPok
	println("printf commitmentPok")
	for i := 0; i < len(output.commitmentPok); i++ {
		println(output.commitmentPok[i].String())
	}
}
