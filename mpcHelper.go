// Provides the generation and verification methods for the MPC process
package circom

import (
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"os"
)

/**
 * Function:InitPhase1
 * @Description: generate an initialization phase1 data and write it to the file
 * @param path: file path
 * @param power: data limit,range:1-27
 * @return phase1: initialization phase1 data
 * @return err: error
 */
func InitPhase1(path string, power int) (phase1 mpcsetup.Phase1, err error) {
	phase1 = mpcsetup.InitPhase1(power)
	FilePhase1Init, err := os.Create(path)
	if err != nil {
		return phase1, err
	}
	_, err = phase1.WriteTo(FilePhase1Init)
	if err != nil {
		return phase1, err
	}
	err = FilePhase1Init.Close()
	if err != nil {
		return phase1, err
	}
	return phase1, nil
}

/**
 * Function:ContributePhase1
 * @Description: participate in the MPC process of phase1
 * @param prevPath: previous round phase1 file path
 * @param nextPath: the writing path of the phase1 file in this round
 * @return prev: previous phase1 data
 * @return next: current phase1 data
 * @return err: error
 */
func ContributePhase1(prevPath string, nextPath string) (prev mpcsetup.Phase1, next mpcsetup.Phase1, err error) {
	prev, err = ReadPhase1FromFile(prevPath)
	if err != nil {
		return mpcsetup.Phase1{}, mpcsetup.Phase1{}, err
	}
	next = phase1clone(prev)
	next.Contribute()
	err = mpcsetup.VerifyPhase1(&prev, &next)
	if err != nil {
		return prev, next, err
	}
	FilePhase1Next, err := os.Create(nextPath)
	if err != nil {
		return prev, next, err
	}
	_, err = next.WriteTo(FilePhase1Next)
	if err != nil {
		return prev, next, err
	}
	return prev, next, nil
}

/**
 * Function:VerifyPhase1
 * @Description: verify phase1 file is calculated correctly
 * @param prevPath: previous round phase1 file path
 * @param curPath: current round phase1 file path
 * @return bool: check result
 * @return error: error
 */
func VerifyPhase1(prevPath string, curPath string) (bool, error) {
	prev, err := ReadPhase1FromFile(prevPath)
	if err != nil {
		return false, err
	}
	cur, err := ReadPhase1FromFile(curPath)
	if err != nil {
		return false, err
	}
	err = mpcsetup.VerifyPhase1(&prev, &cur)
	if err != nil {
		return false, err
	}
	return true, nil
}

/**
 * Function:InitPhase2
 * @Description: generate an initialization phase2 data and write it to the file
 * @param ccs: circuit constraints
 * @param phase1Path: phase1 data file path
 * @param phase2Path: phase2 data file path
 * @return evals:  phase1.5 data
 * @return phase1: phase1 data
 * @return phase2: initialization phase2 data
 * @return err: error
 */
func InitPhase2(ccs constraint.ConstraintSystem, phase1Path string, phase2Path string) (evals mpcsetup.Phase2Evaluations, phase1 mpcsetup.Phase1, phase2 mpcsetup.Phase2, err error) {
	phase1, err = ReadPhase1FromFile(phase1Path)
	if err != nil {
		return mpcsetup.Phase2Evaluations{}, mpcsetup.Phase1{}, mpcsetup.Phase2{}, err
	}
	r1cs := ccs.(*cs.R1CS)
	phase2, evals = mpcsetup.InitPhase2(r1cs, &phase1)
	FilePhase2Init, err := os.Create(phase2Path)
	if err != nil {
		return evals, phase1, phase2, err
	}
	_, err = phase2.WriteTo(FilePhase2Init)
	if err != nil {
		return evals, phase1, phase2, err
	}
	err = FilePhase2Init.Close()
	if err != nil {
		return evals, phase1, phase2, err
	}
	return evals, phase1, phase2, nil
}

/**
 * Function:ContributePhase2
 * @Description: participate in the MPC process of phase2
 * @param prevPath: previous round phase2 file path
 * @param nextPath: the writing path of the phase2 file in this round
 * @return prev: previous phase2 data
 * @return next: current phase2 data
 * @return err: error
 */
func ContributePhase2(prevPath string, nextPath string) (prev mpcsetup.Phase2, next mpcsetup.Phase2, err error) {
	prev, err = ReadPhase2FromFile(prevPath)
	if err != nil {
		return mpcsetup.Phase2{}, mpcsetup.Phase2{}, err
	}
	next = phase2clone(prev)
	next.Contribute()
	err = mpcsetup.VerifyPhase2(&prev, &next)
	if err != nil {
		return prev, next, err
	}
	FilePhase2Next, err := os.Create(nextPath)
	if err != nil {
		return prev, next, err
	}
	_, err = next.WriteTo(FilePhase2Next)
	if err != nil {
		return prev, next, err
	}
	return prev, next, nil
}

/**
 * Function:VerifyPhase2
 * @Description: verify phase2 file is calculated correctly
 * @param prevPath: previous round phase2 file path
 * @param curPath: current round phase2 file path
 * @return bool: check result
 * @return error: error
 */
func VerifyPhase2(prevPath string, curPath string) (bool, error) {
	prev, err := ReadPhase2FromFile(prevPath)
	if err != nil {
		return false, err
	}
	cur, err := ReadPhase2FromFile(curPath)
	if err != nil {
		return false, err
	}
	err = mpcsetup.VerifyPhase2(&prev, &cur)
	if err != nil {
		return false, err
	}
	return true, nil
}

/**
 * Function:phase1clone
 * @Description: clone phase1 data
 * @param phase1: phase1 data
 * @return: copy of phase1 data
 */
func phase1clone(phase1 mpcsetup.Phase1) mpcsetup.Phase1 {
	r := mpcsetup.Phase1{}
	r.Parameters.G1.Tau = append(r.Parameters.G1.Tau, phase1.Parameters.G1.Tau...)
	r.Parameters.G1.AlphaTau = append(r.Parameters.G1.AlphaTau, phase1.Parameters.G1.AlphaTau...)
	r.Parameters.G1.BetaTau = append(r.Parameters.G1.BetaTau, phase1.Parameters.G1.BetaTau...)

	r.Parameters.G2.Tau = append(r.Parameters.G2.Tau, phase1.Parameters.G2.Tau...)
	r.Parameters.G2.Beta = phase1.Parameters.G2.Beta

	r.PublicKeys = phase1.PublicKeys
	r.Hash = append(r.Hash, phase1.Hash...)
	return r
}

/**
 * Function:phase2clone
 * @Description: clone phase2 data
 * @param phase2: phase2 data
 * @return: copy of phase2 data
 */
func phase2clone(phase2 mpcsetup.Phase2) mpcsetup.Phase2 {
	r := mpcsetup.Phase2{}
	r.Parameters.G1.Delta = phase2.Parameters.G1.Delta
	r.Parameters.G1.L = append(r.Parameters.G1.L, phase2.Parameters.G1.L...)
	r.Parameters.G1.Z = append(r.Parameters.G1.Z, phase2.Parameters.G1.Z...)
	r.Parameters.G2.Delta = phase2.Parameters.G2.Delta
	r.PublicKey = phase2.PublicKey
	r.Hash = append(r.Hash, phase2.Hash...)
	return r
}

/**
 * Function:ReadPhase1FromFile
 * @Description: get phase1 data from file
 * @param path: file path
 * @return phase1: phase1 data
 * @return err: error
 */
func ReadPhase1FromFile(path string) (phase1 mpcsetup.Phase1, err error) {
	FilePhase1, err := os.Open(path)
	_, err = phase1.ReadFrom(FilePhase1)
	return
}

/**
 * Function:ReadPhase2FromFile
 * @Description: get phase2 data from file
 * @param path: file path
 * @return phase2: phase2 data
 * @return err: error
 */
func ReadPhase2FromFile(path string) (phase2 mpcsetup.Phase2, err error) {
	FilePhase2, err := os.Open(path)
	_, err = phase2.ReadFrom(FilePhase2)
	return
}
