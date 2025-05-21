package mpc

import (
	"os"

	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
)

/**
 * Function: InitInnerPhase2
 * @Description: generate an initialization phase2 data and write it to the file
 * @param ccs: circuit constraints
 * @param phase1Path: phase1 data file path
 * @param phase2Path: phase2 data file path
 * @return evals:  phase1.5 data
 * @return phase1: phase1 data
 * @return phase2: initialization phase2 data
 * @return err: error
 */
func InitInnerPhase2(ccs constraint.ConstraintSystem, srsCommonsPath string, phase2Path string) (evals mpcsetup.Phase2Evaluations, srs mpcsetup.SrsCommons, phase2 mpcsetup.Phase2, err error) {
	srs, err = ReadInnerSrsCommonsFromFile(srsCommonsPath)
	if err != nil {
		return mpcsetup.Phase2Evaluations{}, mpcsetup.SrsCommons{}, mpcsetup.Phase2{}, err
	}
	r1cs := ccs.(*cs.R1CS)
	evals = phase2.Initialize(r1cs, &srs)
	f, err := os.Create(phase2Path)
	if err != nil {
		return evals, srs, phase2, err
	}
	_, err = phase2.WriteTo(f)
	if err != nil {
		return evals, srs, phase2, err
	}
	err = f.Close()
	if err != nil {
		return evals, srs, phase2, err
	}
	return evals, srs, phase2, nil
}

/**
 * Function: ContributeInnerPhase2
 * @Description: participate in the MPC process of phase2
 * @param prevPath: previous round phase2 file path
 * @param nextPath: the writing path of the phase2 file in this round
 * @return next: current phase2 data
 * @return err: error
 */
func ContributeInnerPhase2(prevPath string, nextPath string) (next mpcsetup.Phase2, err error) {
	prev, err := ReadInnerPhase2FromFile(prevPath)
	if err != nil {
		return mpcsetup.Phase2{}, err
	}
	prev.Contribute()
	next = prev
	FilePhase2Next, err := os.Create(nextPath)
	if err != nil {
		return next, err
	}
	_, err = next.WriteTo(FilePhase2Next)
	if err != nil {
		return next, err
	}
	return next, nil
}

/**
 * Function: VerifyInnerPhase2
 * @Description: verify phase2 file is calculated correctly
 * @param prevPath: previous round phase2 file path
 * @param curPath: current round phase2 file path
 * @return []byte: the hash of previous round phase2
 * @return error: error
 */
func VerifyInnerPhase2(prevPath string, curPath string) ([]byte, error) {
	prev, err := ReadInnerPhase2FromFile(prevPath)
	if err != nil {
		return nil, err
	}
	cur, err := ReadInnerPhase2FromFile(curPath)
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
 * Function: ReadInnerPhase2FromFile
 * @Description: get phase2 data from file
 * @param path: file path
 * @return phase2: phase2 data
 * @return err: error
 */
func ReadInnerPhase2FromFile(path string) (mpcsetup.Phase2, error) {
	var phase2 mpcsetup.Phase2
	f, err := os.Open(path)
	if err != nil {
		return phase2, err
	}
	_, err = phase2.ReadFrom(f)
	return phase2, err
}
