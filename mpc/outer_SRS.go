package mpc

import (
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"os"
)

/**
 * Function: InitInnerPhase1
 * @Description: generate an initialization phase1 data and write it to the file
 * @param path: file path
 * @param power: data limit, range:1-27
 * @return phase1: initialization phase1 data
 * @return err: error
 */
func InitOuterSRS(path string, srsSize int) (srs kzg_bn254.MpcSetup, err error) {
	srs = kzg_bn254.InitializeSetup(srsSize)
	srs.Contribute()
	f, err := os.Create(path)
	if err != nil {
		return kzg_bn254.MpcSetup{}, err
	}
	_, err = srs.WriteTo(f)
	if err != nil {
		return kzg_bn254.MpcSetup{}, err
	}
	err = f.Close()
	return srs, nil
}

/**
 * Function: ContributeInnerPhase1
 * @Description: participate in the MPC process of phase1
 * @param prevPath: previous round phase1 file path
 * @param nextPath: the writing path of the phase1 file in this round
 * @return next: current phase1 data
 * @return err: error
 */
func ContributeOuterSRS(prevPath string, nextPath string, srsSize int) (next kzg_bn254.MpcSetup, err error) {
	pre, err := ReadOuterSRSFromFile(prevPath, srsSize)
	if err != nil {
		return kzg_bn254.MpcSetup{}, err
	}
	pre.Contribute()
	next = pre
	out, err := os.Create(nextPath)
	if err != nil {
		return kzg_bn254.MpcSetup{}, err
	}
	_, err = pre.WriteTo(out)
	if err != nil {
		return kzg_bn254.MpcSetup{}, err
	}
	err = out.Close()
	return next, nil
}

/**
 * Function: VerifyInnerPhase1
 * @Description: verify phase1 file is calculated correctly
 * @param prevPath: previous round phase1 file path
 * @param curPath: current round phase1 file path
 * @return []byte: the hash of previous round phase1
 * @return error: error
 */

func VerifyinitOuterSRS(path string, srsSize int) error {
	p, err := ReadOuterSRSFromFile(path, srsSize)
	if err != nil {
		return err
	}
	srs := kzg_bn254.InitializeSetup(srsSize)
	err = srs.Verify(&p)
	if err != nil {
		return err
	}
	return nil
}

func VerifyOuterSRS(prevPath string, curPath string, srsSize int) error {
	pre, err := ReadOuterSRSFromFile(prevPath, srsSize)
	if err != nil {
		return err
	}
	cur, err := ReadOuterSRSFromFile(curPath, srsSize)
	if err != nil {
		return err
	}
	err = pre.Verify(&cur)
	if err != nil {
		return err
	}
	return nil
}

/**
 * Function: InnerSeal
 * @Description: Convert phase1 to srs public string
 * @param phase1Path: phase1 file path
 * @param outputPath: current round phase1 file path
 * @return srs: common srs
 * @return err: error
 */
func OuterSRSSeal(inputPath string, srsSize int) (srs kzg_bn254.SRS, err error) {
	prev, err := ReadOuterSRSFromFile(inputPath, srsSize)
	if err != nil {
		return srs, err
	}
	beaconChallenge := []byte("beacon SRS")
	srs = prev.Seal(beaconChallenge)
	return srs, nil
}

/**
 * Function: ReadInnerPhase1FromFile
 * @Description: get phase1 data from file
 * @param path: file path
 * @return phase1: phase1 data
 * @return err: error
 */
func ReadOuterSRSFromFile(path string, srsSize int) (kzg_bn254.MpcSetup, error) {
	srs := kzg_bn254.InitializeSetup(srsSize)
	in, err := os.Open(path)
	if err != nil {
		return kzg_bn254.MpcSetup{}, err
	}
	_, err = srs.ReadFrom(in)
	if err != nil {
		return kzg_bn254.MpcSetup{}, err
	}
	err = in.Close()
	if err != nil {
		return kzg_bn254.MpcSetup{}, err
	}
	return srs, err
}
