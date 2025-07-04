package mpc

import (
	"os"

	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
)

/**
 * Function: InitPhase2
 * @Description: generate an initialization phase2 data and write it to the file
 * @param ccs: circuit constraints
 * @param phase1Path: phase1 data file path
 * @param phase2Path: phase2 data file path
 * @return evals:  phase1.5 data
 * @return phase1: phase1 data
 * @return phase2: initialization phase2 data
 * @return err: error
 */
func InitPhase2(ccs constraint.ConstraintSystem, srsCommonsPath string, phase2Path string) (*mpcsetup.Phase2Evaluations, *mpcsetup.SrsCommons, *mpcsetup.Phase2, error) {
	srs, err := ReadSrsCommonsFromFile(srsCommonsPath)
	if err != nil {
		return nil, nil, nil, err
	}
	r1cs := ccs.(*cs.R1CS)
	p := new(mpcsetup.Phase2)
	evals := p.Initialize(r1cs, srs)

	f, err := os.Create(phase2Path)
	if err != nil {
		return nil, nil, nil, err
	}
	defer f.Close()

	_, err = p.WriteTo(f)
	if err != nil {
		return nil, nil, nil, err
	}
	return &evals, srs, p, nil
}

/**
 * Function: ContributePhase2
 * @Description: participate in the MPC process of phase2
 * @param prevPath: previous round phase2 file path
 * @param nextPath: the writing path of the phase2 file in this round
 * @return next: current phase2 data
 * @return err: error
 */
func ContributePhase2(prevPath string, nextPath string) (*mpcsetup.Phase2, error) {
	p, err := ReadPhase2FromFile(prevPath)
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
 * Function: VerifyPhase2
 * @Description: verify phase2 file is calculated correctly
 * @param prevPath: previous round phase2 file path
 * @param curPath: current round phase2 file path
 * @return []byte: the hash of previous round phase2
 * @return error: error
 */
func VerifyPhase2(prevPath string, curPath string) ([]byte, error) {
	prev, err := ReadPhase2FromFile(prevPath)
	if err != nil {
		return nil, err
	}
	cur, err := ReadPhase2FromFile(curPath)
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
 * Function: ReadPhase2FromFile
 * @Description: get phase2 data from file
 * @param path: file path
 * @return phase2: phase2 data
 * @return err: error
 */
func ReadPhase2FromFile(path string) (*mpcsetup.Phase2, error) {
	p := new(mpcsetup.Phase2)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	_, err = p.ReadFrom(f)
	if err != nil {
		return nil, err
	}
	return p, nil
}
