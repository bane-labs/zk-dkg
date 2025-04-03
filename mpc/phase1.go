package mpc

import (
	"os"

	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
)

/**
 * Function: InitPhase1
 * @Description: generate an initialization phase1 data and write it to the file
 * @param path: file path
 * @param power: data limit, range:1-27
 * @return phase1: initialization phase1 data
 * @return err: error
 */
func InitPhase1(path string, power uint64) (phase1 mpcsetup.Phase1, err error) {
	phase1.Initialize(power)
	f, err := os.Create(path)
	if err != nil {
		return phase1, err
	}
	_, err = phase1.WriteTo(f)
	if err != nil {
		return phase1, err
	}
	err = f.Close()
	if err != nil {
		return phase1, err
	}
	return phase1, nil
}

/**
 * Function: ContributePhase1
 * @Description: participate in the MPC process of phase1
 * @param prevPath: previous round phase1 file path
 * @param nextPath: the writing path of the phase1 file in this round
 * @return next: current phase1 data
 * @return err: error
 */
func ContributePhase1(prevPath string, nextPath string) (next mpcsetup.Phase1, err error) {
	prev, err := ReadPhase1FromFile(prevPath)
	if err != nil {
		return mpcsetup.Phase1{}, err
	}
	prev.Contribute()
	next = prev
	f, err := os.Create(nextPath)
	if err != nil {
		return next, err
	}
	_, err = next.WriteTo(f)
	if err != nil {
		return next, err
	}
	return next, nil
}

/**
 * Function: VerifyPhase1
 * @Description: verify phase1 file is calculated correctly
 * @param prevPath: previous round phase1 file path
 * @param curPath: current round phase1 file path
 * @return []byte: the hash of previous round phase1
 * @return error: error
 */
func VerifyPhase1(prevPath string, curPath string) ([]byte, error) {
	prev, err := ReadPhase1FromFile(prevPath)
	if err != nil {
		return nil, err
	}
	cur, err := ReadPhase1FromFile(curPath)
	if err != nil {
		return nil, err
	}
	err = prev.Verify(&cur)
	if err != nil {
		return nil, err
	}
	return cur.Challenge, nil
}

/**
 * Function: Seal
 * @Description: Convert phase1 to srs public string
 * @param phase1Path: phase1 file path
 * @param outputPath: current round phase1 file path
 * @return srs: common srs
 * @return err: error
 */
func Seal(phase1Path string, outputPath string) (srs mpcsetup.SrsCommons, err error) {
	prev, err := ReadPhase1FromFile(phase1Path)
	if err != nil {
		return srs, err
	}
	beaconChallenge := []byte("beacon Phase 1")
	srs = prev.Seal(beaconChallenge)
	f, err := os.Create(outputPath)
	if err != nil {
		return srs, err
	}
	_, err = srs.WriteTo(f)
	if err != nil {
		return srs, err
	}
	return srs, nil
}

/**
 * Function: ReadPhase1FromFile
 * @Description: get phase1 data from file
 * @param path: file path
 * @return phase1: phase1 data
 * @return err: error
 */
func ReadPhase1FromFile(path string) (mpcsetup.Phase1, error) {
	var phase1 mpcsetup.Phase1
	f, err := os.Open(path)
	if err != nil {
		return phase1, err
	}
	_, err = phase1.ReadFrom(f)
	return phase1, err
}

func ReadSrsCommonsFromFile(path string) (mpcsetup.SrsCommons, error) {
	var srs mpcsetup.SrsCommons
	f, err := os.Open(path)
	if err != nil {
		return srs, err
	}
	_, err = srs.ReadFrom(f)
	return srs, err
}
