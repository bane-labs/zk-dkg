package mpc

import (
	"crypto/rand"
	"io"
	"os"

	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
)

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
	srs, err := SealPlonkSRS(srsPath, srsSize)
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
 * Function: ExportOuterProvingKey
 * @Description: export proving key file
 * @param pk: proving key
 * @param path: proving key file path
 */
func ExportPlonkProvingKey(pk plonk.ProvingKey, path string) error {
	return writeSecureAtomic(path, pk)
}

/**
 * Function: ExportPlonkVerifyingKey
 * @Description: export verifying key file
 * @param vk: verifying key
 * @param path: verifying key file path
 */
func ExportPlonkVerifyingKey(vk plonk.VerifyingKey, path string) error {
	return writeSecureAtomic(path, vk)
}

/**
 * Function: ExportCCS
 * @Description: export r1cs file
 * @param ccs: r1cs
 */
func ExportCCS(ccs constraint.ConstraintSystem, path string) error {
	return writeSecureAtomic(path, ccs)
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
	//VK := vk.(*plonk_bn254.VerifyingKey)
	//err = VK.ExportSolidity(contract, solidity.WithHashToFieldFunction(sha256.New()))
	err = vk.ExportSolidity(contract)
	if err != nil {
		return err
	}
	return nil
}

type Exportable interface {
	WriteTo(w io.Writer) (int64, error)
}

// writeSecureAtomic writes data to a temporary file with secure permissions and then atomically renames it to the final path.
// It ensures that the file is written completely before renaming, and it handles errors by securely.
func writeSecureAtomic(finalPath string, data Exportable) error {
	// Create temporary file with restrictive permissions
	tempPath := finalPath + ".tmp"
	out, err := os.OpenFile(tempPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return err
	}

	defer func() {
		out.Close()
		// Secure cleanup: overwrite and delete temp file on failure
		if err != nil {
			secureDelete(tempPath)
		}
	}()

	// Write data completely
	_, err = data.WriteTo(out)
	if err != nil {
		return err
	}

	// Ensure data is written to disk
	err = out.Sync()
	if err != nil {
		return err
	}

	err = out.Close()
	if err != nil {
		return err
	}

	// Atomic rename
	return os.Rename(tempPath, finalPath)
}

// secureDelete securely deletes a file by overwriting it with random data before removing it.
func secureDelete(path string) {
	if file, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		// Overwrite with random data
		stat, _ := file.Stat()
		randomData := make([]byte, stat.Size())
		rand.Read(randomData)
		file.WriteAt(randomData, 0)
		file.Sync()
		file.Close()
	}
	os.Remove(path)
}
