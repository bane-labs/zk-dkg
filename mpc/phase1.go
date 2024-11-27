package mpc

import (
	"os"

	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
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
 * Function:ReadPhase1FromFile
 * @Description: get phase1 data from file
 * @param path: file path
 * @return phase1: phase1 data
 * @return err: error
 */
func ReadPhase1FromFile(path string) (mpcsetup.Phase1, error) {
	var phase1 mpcsetup.Phase1
	FilePhase1, err := os.Open(path)
	if err != nil {
		return phase1, err
	}
	_, err = phase1.ReadFrom(FilePhase1)
	return phase1, err
}
