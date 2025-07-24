package mpc

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
	"os"

	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
)

/**
 * Function: SealKeysFromExistedMPC
 * @Description: seal proving key and verification key required for zk proof calculation from the existing MPC file
 * @param ccs: circuit constraints
 * @param srsPath: phase1 SRS file path required for proof calculation
 * @param beaconChallenge: a random beacon of moderate entropy evaluated at a time later than the latest contribution, as the final contribution
 * @param phase2Path: phase2 file path required for proof calculation
 * @return pk: proving key
 * @return vk: verification key
 * @return err: error
 */
func SealKeysFromExistedMPC(ccs constraint.ConstraintSystem, srsPath string, beaconChallenge string, phase2Path string) (*groth16.ProvingKey, *groth16.VerifyingKey, error) {
	// Get phase1 data
	srs, err := ReadSrsCommonsFromFile(srsPath)
	if err != nil {
		return nil, nil, err
	}
	// Get phase1.5 data
	r1cs := ccs.(*cs.R1CS)
	p2 := new(mpcsetup.Phase2)
	evals := p2.Initialize(r1cs, srs)
	// Get phase2 data
	phase2, err := ReadPhase2FromFile(phase2Path)
	if err != nil {
		return nil, nil, err
	}
	// Generate proving and verifying keys
	pk, vk := phase2.Seal(srs, &evals, []byte(beaconChallenge))
	return pk.(*groth16.ProvingKey), vk.(*groth16.VerifyingKey), nil
}

/**
 * Function: ExportProvingKey
 * @Description: export proving key file
 * @param pk: proving key
 */
func ExportProvingKey(pk *groth16.ProvingKey, path string) error {
	return writeSecureAtomic(path, pk)
}

/**
 * Function: ExportVerifyingKey
 * @Description: export verifying key file
 * @param vk: verifying key
 */
func ExportVerifyingKey(vk *groth16.VerifyingKey, path string) error {
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
func ExportContract(vk *groth16.VerifyingKey, path string) error {
	contract, err := os.Create(path)
	if err != nil {
		return err
	}
	return vk.ExportSolidity(contract, solidity.WithHashToFieldFunction(sha256.New()))
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
