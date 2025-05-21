package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"os"
	"time"

	"github.com/consensys/gnark/backend/plonk"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend/cs/scs"

	"github.com/bane-labs/zk-dkg/circuit"
	"github.com/bane-labs/zk-dkg/helper"
	"github.com/bane-labs/zk-dkg/mpc"
	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"

	"github.com/urfave/cli/v2"
)

const (
	DefaultPhase1FilePrefix = "InnerPhase1_"
	DefaultPhase2FilePrefix = "InnerPhase2_"
)

var batchArray = [3]int{1, 2, 7}
var MaxBatch = 7
var (
	// Flags for MPC
	innerPhase1FileFlag = &cli.PathFlag{
		Name:  "innerPhase1file",
		Usage: "The input file path of a inner phase1 contribution file",
	}
	innerPhase2FileFlag = &cli.PathFlag{
		Name:  "innerPhase2file",
		Usage: "The input file path of a inner phase2 contribution file",
	}
	innerSrsFileFlag = &cli.PathFlag{
		Name:  "innerSrsfile",
		Usage: "The input file path of a phase1 SRS file",
	}
	inputFileFlag = &cli.PathFlag{
		Name:  "input",
		Usage: "The input file path of a MPC contribution",
	}
	outputFileFlag = &cli.PathFlag{
		Name:  "output",
		Usage: "The out file path of a MPC contribution",
	}
	// Flags for contract generation
	innerPKFileFlag = &cli.PathFlag{
		Name:  "innerProvingkey",
		Usage: "The output file path of inner proving key",
		Value: "inner_Pk",
	}
	innerVKFileFlag = &cli.PathFlag{
		Name:  "innerVerifyingkey",
		Usage: "The output file path of inner verifying key",
		Value: "inner_vk",
	}
	innerCcsFileFlag = &cli.PathFlag{
		Name:  "innerCcs",
		Usage: "The output file path of inner ccs",
		Value: "inner_ccs",
	}
	outerSrsFileFlag = &cli.PathFlag{
		Name:  "outerSrsfile",
		Usage: "The file path of a outer SRS file",
	}
	outerCcssFolderFlag = &cli.PathFlag{
		Name:  "outerCssFolder",
		Usage: "The output folder path of outer ccs",
		Value: "outer",
	}
	outerPKsFolderFlag = &cli.PathFlag{
		Name:  "outerPKsFolder",
		Usage: "The output folder path of outer pk",
		Value: "outer",
	}
	outerVKsFolderFlag = &cli.PathFlag{
		Name:  "outerPKsFolder",
		Usage: "The output folder path of outer vk",
		Value: "outer",
	}
	outerContractsFolderFlag = &cli.PathFlag{
		Name:  "outerContractsFolder",
		Usage: "The output folder path of outer contract",
		Value: "outer",
	}
)

func main() {
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:  "innerPhase1",
				Usage: "Deal with MPC phase1",
				Description: `
Phase1 commands deal the generation of Groth16 setup parameters,
should be performed before any ZK application deployed based on
this algorithm, and later can be used by any phase2 which needs
this MPC.`,
				Subcommands: []*cli.Command{
					{
						Name:   "init",
						Usage:  "Generate init inner phase1 file",
						Action: initInnerPhase1,
						Flags: []cli.Flag{
							outputFileFlag,
						},
						Description: `
	phase1 init --output <filepath>

will generate a phase1 file without any input, should be used by
the first participant to generate the first file.`,
					},
					{
						Name:   "verify",
						Usage:  "Verify inner phase1 file step forward",
						Action: verifyInnerPhase1,
						Flags: []cli.Flag{
							inputFileFlag,
							outputFileFlag,
						},
						Description: `
	phase1 verify --phase1file <filepath> --output <filepath>

will verify the contribute operation that takes place on the input
file to the output file, should be used before any further contribution
to the unverified output file.`,
					},
					{
						Name:   "contribute",
						Usage:  "Contribute to the inner phase1 MPC",
						Action: contributeInnerPhase1,
						Flags: []cli.Flag{
							inputFileFlag,
							outputFileFlag,
						},
						Description: `
	phase1 contribute --phase1file <filepath> --output <filepath>

will generate a new phase1 file based on the input one, every
participant should do this only once and one by one, so that a
chain of this contribute operations realize a MPC.`,
					},
					{
						Name:   "seal",
						Usage:  "Convert inner Phase1 data to common SRS",
						Action: sealInnerPhase1,
						Flags: []cli.Flag{
							innerPhase1FileFlag,
							outputFileFlag,
						},
						Description: `
	phase1 seal --phase1file <filepath> --output <filepath>

will convert Phase1 data to common srs,each participant can execute this operation locally to verify that the correct public SRS string is used`,
					},
				},
			},
			{
				Name:  "innerPhase2",
				Usage: "Deal with MPC inner phase2",
				Description: `
Phase2 commands deal the generation of circuit setup parameters,
should be performed before every ZK application deployed based on
phase1, and later can be used by this application repeatedly.`,
				Subcommands: []*cli.Command{
					{
						Name:   "init",
						Usage:  "Generate the first inner phase2 file",
						Action: initInnerPhase2,
						Flags: []cli.Flag{
							innerSrsFileFlag,
							outputFileFlag,
							innerCcsFileFlag,
						},
						Description: `
	phase2 init --srsfile <filepath> --output <filepath>

will generate a phase2 file with a phase1 input, should be used by
the first participant to generate the first file. A parameter "batch"
is required by circuit definition, which depends on the amount of
input message, please refer
https://github.com/bane-labs/zk-dkg/blob/v0.1.0/circuit/batch_encryption.go#L33`,
					},
					{
						Name:   "verify",
						Usage:  "Verify the inner phase2 file step forward",
						Action: verifyInnerPhase2,
						Flags: []cli.Flag{
							inputFileFlag,
							outputFileFlag,
						},
						Description: `
	phase2 verify --phase2file <filepath> --output <filepath>

will verify the contribute operation that takes place on the input
file to the output file, should be used before any further contribution
to the unverified output file.`,
					},
					{
						Name:   "contribute",
						Usage:  "Contribute to the inner phase2 MPC",
						Action: contributeInnerPhase2,
						Flags: []cli.Flag{
							inputFileFlag,
							outputFileFlag,
						},
						Description: `
	phase2 contribute --phase2file <filepath> --output <filepath>

will generate a new phase2 file based on the input one, every
participant should do this only once and one by one, so that a
chain of this contribute operations realize a MPC.`,
					},
				},
			},
			{
				Name:   "innerSeal",
				Usage:  "Export the proving key, verifying key and the verifier contract",
				Action: exportInnerSeal,
				Flags: []cli.Flag{
					innerSrsFileFlag,
					innerPhase2FileFlag,
					innerPKFileFlag,
					innerVKFileFlag,
					innerCcsFileFlag,
				},
				Description: `
	seal --srsfile <filepath> --phase2file <filepath> --provingkey <filepath> --verifyingkey <filepath> --r1cs <filepath>

will generate a proving key file, a verifying key file, and a
Solidity verifier contract based on the input MPC phase1 and
phase2 files, the same parameter "batch" used in "phase2 init"
should also be provided, please refer
https://github.com/bane-labs/zk-dkg/blob/v0.1.0/circuit/batch_encryption.go#L33.`,
			},
			{
				Name:  "outerSRS",
				Usage: "Deal with MPC outerSRS",
				Description: `
Phase1 commands deal the generation of Groth16 setup parameters,
should be performed before any ZK application deployed based on
this algorithm, and later can be used by any phase2 which needs
this MPC.`,
				Subcommands: []*cli.Command{
					{
						Name:   "init",
						Usage:  "Generate init outer srs file",
						Action: initOuterSRS,
						Flags: []cli.Flag{
							innerCcsFileFlag,
							innerPKFileFlag,
							innerVKFileFlag,
							outerSrsFileFlag,
							outerCcssFolderFlag,
						},
						Description: `
	phase1 init --output <filepath>

will generate a phase1 file without any input, should be used by
the first participant to generate the first file.`,
					},
					{
						Name:   "checkInit",
						Usage:  "Verify init outer srs file step forward",
						Action: verifyInitOuterSRS,
						Flags: []cli.Flag{
							outerSrsFileFlag,
							outerCcssFolderFlag,
						},
						Description: `
	phase1 verify --phase1file <filepath> --output <filepath>

will verify the contribute operation that takes place on the input
file to the output file, should be used before any further contribution
to the unverified output file.`,
					},
					{
						Name:   "verify",
						Usage:  "Verify outer srs file step forward",
						Action: verifyOuterSRS,
						Flags: []cli.Flag{
							inputFileFlag,
							outputFileFlag,
							outerCcssFolderFlag,
						},
						Description: `
	phase1 verify --phase1file <filepath> --output <filepath>

will verify the contribute operation that takes place on the input
file to the output file, should be used before any further contribution
to the unverified output file.`,
					},
					{
						Name:   "contribute",
						Usage:  "Contribute to the outer srs MPC",
						Action: contributeOuterSRS,
						Flags: []cli.Flag{
							inputFileFlag,
							outputFileFlag,
							outerCcssFolderFlag,
						},
						Description: `
	phase1 contribute --phase1file <filepath> --output <filepath>

will generate a new phase1 file based on the input one, every
participant should do this only once and one by one, so that a
chain of this contribute operations realize a MPC.`,
					},
					{
						Name:   "seal",
						Usage:  "Convert outer srs data to common SRS",
						Action: exportOuterSeal,
						Flags: []cli.Flag{
							outerCcssFolderFlag,
							outerPKsFolderFlag,
							outerVKsFolderFlag,
							outerContractsFolderFlag,
							outerSrsFileFlag,
						},
						Description: `
	phase1 seal --phase1file <filepath> --output <filepath>

will convert Phase1 data to common srs,each participant can execute this operation locally to verify that the correct public SRS string is used`,
					},
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func initOuterSRS(ctx *cli.Context) error {
	innerCcsFilePath := ctx.Path(innerCcsFileFlag.Name)
	if innerCcsFilePath == "" {
		return errors.New("invalid inner css file path")
	}
	innerPKFilePath := ctx.Path(innerPKFileFlag.Name)
	if innerPKFilePath == "" {
		return errors.New("invalid inner provingkey file path")
	}
	innerVKFilePath := ctx.Path(innerVKFileFlag.Name)
	if innerVKFilePath == "" {
		return errors.New("invalid inner verifyingKey file path")
	}

	outerSRSFilePath := ctx.Path(outerSrsFileFlag.Name)
	if outerSRSFilePath == "" {
		return errors.New("invalid outer SRS file path")
	}
	outerCcssFolderPath := ctx.Path(outerCcssFolderFlag.Name)
	if outerCcssFolderPath == "" {
		return errors.New("invalid outer css folder path")
	}
	for i := 0; i < len(batchArray); i++ {
		batch := batchArray[i]
		innerCcss, _, innerVKs := circuit.ComputeMultipleKeyShareEncryptionCircuitByFile(batch, innerCcsFilePath, innerPKFilePath, innerVKFilePath)
		outerCircuit := circuit.ComputeRecursionEncryptionCircuit(batch, innerCcss, innerVKs)
		outerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, outerCircuit)
		if err != nil {
			return err
		}
		r1CS := outerCcs.(*cs.SparseR1CS)
		helper.ExportCSS(outerCcs, fmt.Sprintf("%s_%d_outer_css", outerCcssFolderPath, batchArray[i]))

		if i == MaxBatch {
			srsSize, _ := plonk.SRSSize(r1CS)
			p, err := mpc.InitOuterSRS(outerSRSFilePath, srsSize)
			if err != nil {
				return err
			}
			sha := sha256.New()
			if _, err := p.WriteTo(sha); err != nil {
				panic(err)
			}
			fmt.Println("Outer SRS File challenge:", hex.EncodeToString(sha.Sum(nil)))
		}
	}

	return nil
}

func verifyInitOuterSRS(ctx *cli.Context) error {
	prePath := ctx.Path(outerSrsFileFlag.Name)
	if prePath == "" {
		return errors.New("invalid previous outer srs file path")
	}

	outerCcssFolderPath := ctx.Path(outerCcssFolderFlag.Name)
	if outerCcssFolderPath == "" {
		return errors.New("invalid outer ccs folder path")
	}
	ccs, err := helper.ReadCSS(fmt.Sprintf("%s_%d_outer_css", outerCcssFolderPath, MaxBatch))
	if err != nil {
		return err
	}
	r1CS := ccs.(*cs.SparseR1CS)
	srsSize, _ := plonk.SRSSize(r1CS)
	err = mpc.VerifyinitOuterSRS(prePath, srsSize)
	if err != nil {
		return err
	}
	fmt.Println("init outer SRS verified")
	return nil
}

func verifyOuterSRS(ctx *cli.Context) error {
	prePath := ctx.Path(inputFileFlag.Name)
	if prePath == "" {
		return errors.New("invalid previous outer srs file path")
	}
	curPath := ctx.Path(outputFileFlag.Name)
	if curPath == "" {
		return errors.New("invalid current output file path")
	}
	outerCcssFolderPath := ctx.Path(outerCcssFolderFlag.Name)
	if outerCcssFolderPath == "" {
		return errors.New("invalid outer ccs folder path")
	}
	ccs, err := helper.ReadCSS(fmt.Sprintf("%s_%d_outer_css", outerCcssFolderPath, MaxBatch))
	if err != nil {
		return err
	}
	r1CS := ccs.(*cs.SparseR1CS)
	srsSize, _ := plonk.SRSSize(r1CS)
	err = mpc.VerifyOuterSRS(prePath, curPath, srsSize)
	if err != nil {
		return err
	}
	fmt.Println("Current outer SRS verified")
	return nil
}

func contributeOuterSRS(ctx *cli.Context) error {
	inputPath := ctx.Path(inputFileFlag.Name)
	if inputPath == "" {
		return errors.New("invalid outer srs file path")
	}
	outputPath := ctx.Path(outputFileFlag.Name)
	if outputPath == "" {
		return errors.New("invalid outer srs output file path")
	}
	outerCcssFolderPath := ctx.Path(outerCcssFolderFlag.Name)
	if outerCcssFolderPath == "" {
		return errors.New("invalid outer ccs folder path")
	}
	ccs, err := helper.ReadCSS(fmt.Sprintf("%s_%d_outer_css", outerCcssFolderPath, MaxBatch))
	if err != nil {
		return err
	}
	r1CS := ccs.(*cs.SparseR1CS)
	srsSize, _ := plonk.SRSSize(r1CS)

	p, err := mpc.ContributeOuterSRS(inputPath, outputPath, srsSize)
	if err != nil {
		return err
	}
	fmt.Println("OuterSRS Contributed OK:")
	sha := sha256.New()
	if _, err := p.WriteTo(sha); err != nil {
		panic(err)
	}
	fmt.Println("outer srs file challenge:", hex.EncodeToString(sha.Sum(nil)))
	return nil
}

func exportOuterSeal(ctx *cli.Context) error {
	outerCcsFolderPath := ctx.Path(outerCcssFolderFlag.Name)
	if outerCcsFolderPath == "" {
		return errors.New("invalid outer css folder path")
	}
	outerPKFolderPath := ctx.Path(outerPKsFolderFlag.Name)
	if outerPKFolderPath == "" {
		return errors.New("invalid outer provingKey folder path")
	}
	outerVKFolderPath := ctx.Path(outerVKsFolderFlag.Name)
	if outerVKFolderPath == "" {
		return errors.New("invalid outer verifyingKey folder path")
	}
	outerContractFolderPath := ctx.Path(outerContractsFolderFlag.Name)
	if outerContractFolderPath == "" {
		return errors.New("invalid outer contract folder path")
	}
	inputSRSFilePath := ctx.Path(outerSrsFileFlag.Name)
	if inputSRSFilePath == "" {
		return errors.New("invalid outer srs file path")
	}
	for i := 0; i < len(batchArray); i++ {
		outerCcs, err := helper.ReadCSS(fmt.Sprintf("%s_%d_outer_css", outerCcsFolderPath, batchArray[i]))
		if err != nil {
			return err
		}
		pk, vk, err := helper.GetParamsFromOuterExistedMPCSetUp(outerCcs, inputSRSFilePath)
		if err != nil {
			return err
		}
		helper.ExportOuterProvingKey(pk, fmt.Sprintf("%s_%d_outer_pk", outerPKFolderPath, batchArray[i]))
		helper.ExportOuterVerifyingKey(vk, fmt.Sprintf("%s_%d_outer_pk", outerVKFolderPath, batchArray[i]))
		helper.ExportContract(vk, fmt.Sprintf("%s_%d_contract.sol", outerContractFolderPath, batchArray[i]))
	}
	return nil
}

func exportInnerSeal(ctx *cli.Context) error {
	srsFilePath := ctx.Path(innerSrsFileFlag.Name)
	if srsFilePath == "" {
		return errors.New("invalid inner phase1 SRS file path")
	}
	phase2FilePath := ctx.Path(innerPhase2FileFlag.Name)
	if phase2FilePath == "" {
		return errors.New("invalid inner phase2 file path")
	}
	innerPKFilePath := ctx.Path(innerPKFileFlag.Name)
	if innerPKFilePath == "" {
		return errors.New("invalid inner provingkey file path")
	}
	innerVKFilePath := ctx.Path(innerVKFileFlag.Name)
	if innerVKFilePath == "" {
		return errors.New("invalid verifyingkey file path")
	}
	r1csFilePath := ctx.Path(innerCcsFileFlag.Name)
	if r1csFilePath == "" {
		return errors.New("invalid r1cs file path")
	}

	css, err := helper.ReadCSS(r1csFilePath)
	if err != nil {
		return err
	}
	pk, vk, err := helper.GetParamsFromInnerExistedMPCSetUp(css, srsFilePath, phase2FilePath)
	if err != nil {
		return err
	}
	helper.ExportInnerProvingKey(pk, innerPKFilePath)
	helper.ExportInnerVerifyingKey(vk, innerVKFilePath)
	return nil
}

func initInnerPhase1(ctx *cli.Context) error {
	path := ctx.Path(outputFileFlag.Name)
	if path == "" {
		path = DefaultPhase1FilePrefix + "1"
	}
	p, err := mpc.InitInnerPhase1(path, uint64(math.Pow(2, 21)))
	if err != nil {
		return err
	}
	sha := sha256.New()
	if _, err := p.WriteTo(sha); err != nil {
		panic(err)
	}
	fmt.Println("File challenge:", hex.EncodeToString(sha.Sum(nil)))
	return nil
}

func verifyInnerPhase1(ctx *cli.Context) error {
	path1 := ctx.Path(inputFileFlag.Name)
	if path1 == "" {
		return errors.New("invalid inner phase1 file path")
	}
	path2 := ctx.Path(outputFileFlag.Name)
	if path2 == "" {
		return errors.New("invalid inner phase1 file path")
	}
	challenge, err := mpc.VerifyInnerPhase1(path1, path2)
	if err != nil {
		return err
	}
	fmt.Println("InnerPhase1 verified, and the previous challenge is", hex.EncodeToString(challenge))
	return nil
}

func contributeInnerPhase1(ctx *cli.Context) error {
	inputPath := ctx.Path(inputFileFlag.Name)
	if inputPath == "" {
		return errors.New("invalid inner phase1 file path")
	}
	outputPath := ctx.Path(outputFileFlag.Name)
	if outputPath == "" {
		return errors.New("invalid inner phase1 file path")
	}
	p, err := mpc.ContributeInnerPhase1(inputPath, outputPath)
	if err != nil {
		return err
	}
	fmt.Println("Contributed to:", hex.EncodeToString(p.Challenge))
	sha := sha256.New()
	if _, err := p.WriteTo(sha); err != nil {
		panic(err)
	}
	fmt.Println("File challenge:", hex.EncodeToString(sha.Sum(nil)))
	return nil
}

func sealInnerPhase1(ctx *cli.Context) error {
	inputPath := ctx.Path(innerPhase1FileFlag.Name)
	if inputPath == "" {
		return errors.New("invalid inner phase1 file path")
	}
	outputPath := ctx.Path(outputFileFlag.Name)
	if outputPath == "" {
		return errors.New("invalid output file path")
	}
	_, err := mpc.InnerSeal(inputPath, outputPath)
	if err != nil {
		return err
	}
	return nil
}

func initInnerPhase2(ctx *cli.Context) error {
	inputPath := ctx.Path(innerSrsFileFlag.Name)
	if inputPath == "" {
		return errors.New("invalid phase1 SRS file path")
	}
	outputpath := ctx.Path(outputFileFlag.Name)
	if outputpath == "" {
		outputpath = DefaultPhase2FilePrefix + "1"
	}
	r1csFilePath := ctx.Path(innerCcsFileFlag.Name)
	if r1csFilePath == "" {
		return errors.New("invalid inner r1cs file path")
	}
	// Generate node private key
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	// Computing public key
	fis := make([]fr_bls12381.Element, 1)
	pubKeys := make([]*ecies.PublicKey, 1)
	for i := 0; i < 1; i++ {
		key, _ := ecies.GenerateKey(rand, crypto.S256(), nil)
		pubKeys[i] = &key.PublicKey
		var fi fr_bls12381.Element
		fi.SetRandom()
		fis[i] = fi
	}
	fisBytes, _, _, _, encryptedFis, _, _ := circuit.PrepareEncryptedKeyShares(pubKeys, fis)
	innerCircuit := circuit.ComputeSingleKeyShareEncryptionCircuit(fisBytes[0], encryptedFis[0])
	css, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, innerCircuit)
	if err != nil {
		return err
	}
	_, _, p, err := mpc.InitInnerPhase2(css, inputPath, outputpath)
	if err != nil {
		return err
	}
	sha := sha256.New()
	if _, err := p.WriteTo(sha); err != nil {
		panic(err)
	}
	fmt.Println("File challenge:", hex.EncodeToString(sha.Sum(nil)))
	helper.ExportCSS(css, r1csFilePath)
	return nil
}

func verifyInnerPhase2(ctx *cli.Context) error {
	path1 := ctx.Path(inputFileFlag.Name)
	if path1 == "" {
		return errors.New("invalid inner phase2 file path")
	}
	path2 := ctx.Path(outputFileFlag.Name)
	if path2 == "" {
		return errors.New("invalid inner phase2 file path")
	}
	challenge, err := mpc.VerifyInnerPhase2(path1, path2)
	if err != nil {
		return err
	}
	fmt.Println("Inner Phase2 verified, and the previous challenge is", hex.EncodeToString(challenge))
	return nil
}

func contributeInnerPhase2(ctx *cli.Context) error {
	inputPath := ctx.Path(inputFileFlag.Name)
	if inputPath == "" {
		return errors.New("invalid inner phase2 file path")
	}
	outputPath := ctx.Path(outputFileFlag.Name)
	if outputPath == "" {
		return errors.New("invalid output file path")
	}
	p, err := mpc.ContributeInnerPhase2(inputPath, outputPath)
	if err != nil {
		return err
	}
	fmt.Println("Contributed to:", hex.EncodeToString(p.Challenge))
	sha := sha256.New()
	if _, err := p.WriteTo(sha); err != nil {
		panic(err)
	}
	fmt.Println("File challenge:", hex.EncodeToString(sha.Sum(nil)))
	return nil
}
