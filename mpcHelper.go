package circom

import (
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"os"
)

func Phase1clone(phase1 mpcsetup.Phase1) mpcsetup.Phase1 {
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

func Phase2clone(phase2 mpcsetup.Phase2) mpcsetup.Phase2 {
	r := mpcsetup.Phase2{}
	r.Parameters.G1.Delta = phase2.Parameters.G1.Delta
	r.Parameters.G1.L = append(r.Parameters.G1.L, phase2.Parameters.G1.L...)
	r.Parameters.G1.Z = append(r.Parameters.G1.Z, phase2.Parameters.G1.Z...)
	r.Parameters.G2.Delta = phase2.Parameters.G2.Delta
	r.PublicKey = phase2.PublicKey
	r.Hash = append(r.Hash, phase2.Hash...)
	return r
}

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

func ContributePhase1(prevPath string, nextPath string) (prev mpcsetup.Phase1, next mpcsetup.Phase1, err error) {
	prev, err = ReadPhase1FromFile(prevPath)
	if err != nil {
		return mpcsetup.Phase1{}, mpcsetup.Phase1{}, err
	}
	next = Phase1clone(prev)
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
	return true, nil
}

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

func ContributePhase2(prevPath string, nextPath string) (prev mpcsetup.Phase2, next mpcsetup.Phase2, err error) {
	prev, err = ReadPhase2FromFile(prevPath)
	if err != nil {
		return mpcsetup.Phase2{}, mpcsetup.Phase2{}, err
	}
	next = Phase2clone(prev)
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
	return true, nil
}

func ReadPhase1FromFile(path string) (phase1 mpcsetup.Phase1, err error) {
	FilePhase1, err := os.Open(path)
	_, err = phase1.ReadFrom(FilePhase1)
	if err != nil {
		return phase1, err
	}
	return phase1, nil
}

func ReadPhase2FromFile(path string) (phase2 mpcsetup.Phase2, err error) {
	FilePhase2, err := os.Open(path)
	_, err = phase2.ReadFrom(FilePhase2)
	if err != nil {
		return phase2, err
	}
	return phase2, nil
}
