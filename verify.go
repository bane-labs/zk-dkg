package circom

import (
	"crypto/sha256"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/solidity"
	"math/big"
	"os"
)

func ExportContract(vk groth16.VerifyingKey) {
	contract, err := os.Create("verify.sol")
	err = vk.ExportSolidity(contract, solidity.WithHashToFieldFunction(sha256.New()))
	if err != nil {
		panic(err)
	}
}

func GetOutputData(proof *groth16.Proof) Output {
	// to do:Calculate parameters required for contract verification

	//print proof public msg
	// Save publicWitness
	/*	schema, _ := frontend.NewSchema(assignment)
		ret, _ := publicWitness.ToJSON(schema)
		var b bytes.Buffer
		json.Indent(&b, ret, "", "\t")
		t.Logf(b.String())*/

	// solidity contract inputs
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
	commitmentCount := int(c.Int64())
	var commitments = make([]big.Int, 2*commitmentCount)
	// commitments
	for i := 0; i < 2*commitmentCount; i++ {
		commitments[i].SetBytes(proofBytes[fpSize*8+4+i*fpSize : fpSize*8+4+(i+1)*fpSize])
		println("commitments:" + commitments[i].String())
	}
	output.commitments = commitments
	var commitmentPok [2]*big.Int
	// commitmentPok
	commitmentPok[0] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize : fpSize*8+4+2*commitmentCount*fpSize+fpSize])
	commitmentPok[1] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize+fpSize : fpSize*8+4+2*commitmentCount*fpSize+2*fpSize])
	output.commitmentPok = commitmentPok[:]
	output.printf()
	return output
}

type Output struct {
	proof         []*big.Int
	commitments   []big.Int
	commitmentPok []*big.Int
}

func (output *Output) printf() {
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
