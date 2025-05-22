package mpc

import (
	"os"

	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
)

/**
 * Function: InitGroth16Phase1
 * @Description: generate an initialization phase1 data and write it to the file
 * @param path: file path
 * @param power: data limit, range:1-27
 * @return phase1: initialization phase1 data
 * @return err: error
 */
func InitGroth16Phase1(path string, power uint64) (*mpcsetup.Phase1, error) {
	p := mpcsetup.NewPhase1(power)
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	_, err = p.WriteTo(f)
	if err != nil {
		return nil, err
	}
	return p, nil
}

/**
 * Function: ContributeGroth16Phase1
 * @Description: participate in the MPC process of phase1
 * @param prevPath: previous round phase1 file path
 * @param nextPath: the writing path of the phase1 file in this round
 * @return next: current phase1 data
 * @return err: error
 */
func ContributeGroth16Phase1(prevPath string, nextPath string) (*mpcsetup.Phase1, error) {
	p, err := ReadGroth16Phase1FromFile(prevPath)
	if err != nil {
		return nil, err
	}
	p.Contribute()
	f, err := os.Create(nextPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	_, err = p.WriteTo(f)
	if err != nil {
		return nil, err
	}
	return p, nil
}

/**
 * Function: VerifyGroth16Phase1
 * @Description: verify phase1 file is calculated correctly
 * @param prevPath: previous round phase1 file path
 * @param curPath: current round phase1 file path
 * @return []byte: the hash of previous round phase1
 * @return error: error
 */
func VerifyGroth16Phase1(prevPath string, curPath string) ([]byte, error) {
	prev, err := ReadGroth16Phase1FromFile(prevPath)
	if err != nil {
		return nil, err
	}
	cur, err := ReadGroth16Phase1FromFile(curPath)
	if err != nil {
		return nil, err
	}
	err = prev.Verify(cur)
	if err != nil {
		return nil, err
	}
	return cur.Challenge, nil
}

/**
 * Function: SealGroth16Phase1
 * @Description: Convert phase1 to srs public string
 * @param phase1Path: phase1 file path
 * @param outputPath: current round phase1 file path
 * @return srs: common srs
 * @return err: error
 */
func SealGroth16Phase1(phase1Path string, outputPath string) (*mpcsetup.SrsCommons, error) {
	p, err := ReadGroth16Phase1FromFile(phase1Path)
	if err != nil {
		return nil, err
	}
	beaconChallenge := []byte("beacon Phase 1")
	srs := p.Seal(beaconChallenge)
	f, err := os.Create(outputPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	_, err = srs.WriteTo(f)
	if err != nil {
		return nil, err
	}
	return &srs, nil
}

/**
 * Function: ReadGroth16Phase1FromFile
 * @Description: get phase1 data from file
 * @param path: file path
 * @return phase1: phase1 data
 * @return err: error
 */
func ReadGroth16Phase1FromFile(path string) (*mpcsetup.Phase1, error) {
	p := new(mpcsetup.Phase1)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	_, err = p.ReadFrom(f)
	return p, err
}

/**
 * Function: ReadGroth16SRSFromFile
 * @Description: get srs data from file
 * @param path: file path
 * @return phase1: srs data
 * @return err: error
 */
func ReadGroth16SRSFromFile(path string) (*mpcsetup.SrsCommons, error) {
	srs := new(mpcsetup.SrsCommons)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	_, err = srs.ReadFrom(f)
	return nil, err
}
