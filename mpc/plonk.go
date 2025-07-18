package mpc

import (
	"crypto/rand"
	"fmt"
	"os"

	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

/**
 * Function: InitPlonkSRS
 * @Description: Initialize an SRS data and write it to the file
 * @param path: file path
 * @param srsSize: data limit, range:1-27
 * @return srs: initialization SRS data
 * @return err: error
 */
func InitPlonkSRS(path string, srsSize int) (*kzg_bn254.MpcSetup, error) {
	if srsSize < 1 || srsSize > 27 {
		return nil, fmt.Errorf("srsSize must be in the range of 1-27, got %d", srsSize)
	}
	srs := kzg_bn254.InitializeSetup(srsSize)
	srs.Contribute()
	// Atomic write with secure permissions
	err := writeSecureAtomic(path, &srs)
	if err != nil {
		return nil, err
	}
	return &srs, nil
}

/**
 * Function: ContributePlonkSRS
 * @Description: participate in the MPC process of Plonk
 * @param prevPath: previous round SRS file path
 * @param nextPath: the writing path of the SRS file in this round
 * @param srsSize: data limit
 * @return next: current SRS data
 * @return err: error
 */
func ContributePlonkSRS(prevPath string, nextPath string, srsSize int) (*kzg_bn254.MpcSetup, error) {
	p, err := ReadPlonkSRSFromFile(prevPath, srsSize)
	if err != nil {
		return nil, err
	}
	p.Contribute()
	// Atomic write with secure permissions
	err = writeSecureAtomic(nextPath, p)
	if err != nil {
		return nil, err
	}
	return p, nil
}

/**
 * Function: VerifyPlonkSRSInitialization
 * @Description: verify SRS file is initialized correctly
 * @param prevPath: previous round SRS file path
 * @param curPath: current round SRS file path
 * @return error: error
 */
func VerifyPlonkSRSInitialization(path string, srsSize int) error {
	p, err := ReadPlonkSRSFromFile(path, srsSize)
	if err != nil {
		return err
	}
	srs := kzg_bn254.InitializeSetup(srsSize)
	err = srs.Verify(p)
	if err != nil {
		return err
	}
	return nil
}

/**
 * Function: VerifyPlonkSRS
 * @Description: verify SRS file is calculated correctly
 * @param prevPath: previous round SRS file path
 * @param curPath: current round SRS file path
 * @param srsSize: data limit
 * @return error: error
 */
func VerifyPlonkSRS(prevPath string, curPath string, srsSize int) error {
	pre, err := ReadPlonkSRSFromFile(prevPath, srsSize)
	if err != nil {
		return err
	}
	cur, err := ReadPlonkSRSFromFile(curPath, srsSize)
	if err != nil {
		return err
	}
	err = pre.Verify(cur)
	if err != nil {
		return err
	}
	return nil
}

/**
 * Function: SealPlonkSRS
 * @Description: Convert SRS to srs public string
 * @param inputPath: SRS file path
 * @param srsSize: data limit
 * @return srs: common srs
 * @return err: error
 */
func SealPlonkSRS(inputPath string, srsSize int) (*kzg_bn254.SRS, error) {
	prev, err := ReadPlonkSRSFromFile(inputPath, srsSize)
	if err != nil {
		return nil, err
	}
	beaconChallenge := []byte("beacon SRS")
	srs := prev.Seal(beaconChallenge)
	return &srs, nil
}

/**
 * Function: ReadPlonkSRSFromFile
 * @Description: get plonk setup from file
 * @param path: file path
 * @param srsSize: data limit
 * @return srs: plonk setup
 * @return err: error
 */
func ReadPlonkSRSFromFile(path string, srsSize int) (*kzg_bn254.MpcSetup, error) {
	srs := kzg_bn254.InitializeSetup(srsSize)
	in, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer in.Close()
	_, err = srs.ReadFrom(in)
	if err != nil {
		return nil, err
	}
	return &srs, err
}

// writeSecureAtomic writes data to a temporary file with secure permissions and then atomically renames it to the final path.
// It ensures that the file is written completely before renaming, and it handles errors by securely.
func writeSecureAtomic(finalPath string, data *kzg_bn254.MpcSetup) error {
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
