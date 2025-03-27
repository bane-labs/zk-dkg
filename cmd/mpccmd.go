package main

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"os"
	"time"

	"github.com/bane-labs/zk-dkg/circuit"
	"github.com/bane-labs/zk-dkg/helper"
	"github.com/bane-labs/zk-dkg/mpc"
	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"

	"github.com/urfave/cli/v2"
)

const (
	DefaultPhase1FilePrefix = "Phase1_"
	DefaultPhase2FilePrefix = "Phase2_"
)

var (
	// Flags for MPC
	inputFileFlag = &cli.PathFlag{
		Name:  "input",
		Usage: "The input file path of a MPC contribution",
	}
	outputFileFlag = &cli.PathFlag{
		Name:  "output",
		Usage: "The out file path of a MPC contribution",
	}
	batchFlag = &cli.IntFlag{
		Name:  "batch",
		Usage: "The expected amount of messages for a circuit to encrypt",
	}
	// Flags for contract generation
	phase1FileFlag = &cli.PathFlag{
		Name:  "phase1file",
		Usage: "The final MPC phase1 file for production",
	}
	phase2FileFlag = &cli.PathFlag{
		Name:  "phase2file",
		Usage: "The final MPC phase2 file for production",
	}
	contractFileFlag = &cli.PathFlag{
		Name:  "contract",
		Usage: "The out file path of contract exportation",
		Value: "Verify.sol",
	}
)

func main() {
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:  "phase1",
				Usage: "Deal with MPC phase1",
				Description: `
Phase1 commands deal the generation of Groth16 setup parameters,
should be performed before any ZK application deployed based on
this algorithm, and later can be used by any phase2 which needs
this MPC.`,
				Subcommands: []*cli.Command{
					{
						Name:   "init",
						Usage:  "Generate the first phase1 file",
						Action: initPhase1,
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
						Usage:  "Verify the phase1 file step forward",
						Action: verifyPhase1,
						Flags: []cli.Flag{
							inputFileFlag,
							outputFileFlag,
						},
						Description: `
	phase1 verify --input <filepath> --output <filepath>

will verify the contribute operation that takes place on the input
file to the output file, should be used before any further contribution
to the unverified output file.`,
					},
					{
						Name:   "contribute",
						Usage:  "Contribute to the phase1 MPC",
						Action: contributePhase1,
						Flags: []cli.Flag{
							inputFileFlag,
							outputFileFlag,
						},
						Description: `
	phase1 contribute --input <filepath> --output <filepath>

will generate a new phase1 file based on the input one, every
participant should do this only once and one by one, so that a
chain of this contribute operations realize a MPC.`,
					},
					{
						Name:   "getCommonSRS",
						Usage:  "Convert Phase1 data to common srs",
						Action: getCommonSRS,
						Flags: []cli.Flag{
							inputFileFlag,
							outputFileFlag,
						},
						Description: `
	phase1 getCommonSRS --input <filepath> --output <filepath>

will convert Phase1 data to common srs,each participant can execute this operation locally to verify that the correct public SRS string is used`,
					},
				},
			},
			{
				Name:  "phase2",
				Usage: "Deal with MPC phase2",
				Description: `
Phase2 commands deal the generation of circuit setup parameters,
should be performed before every ZK application deployed based on
phase1, and later can be used by this application repeatedly.`,
				Subcommands: []*cli.Command{
					{
						Name:   "init",
						Usage:  "Generate the first phase2 file",
						Action: initPhase2,
						Flags: []cli.Flag{
							inputFileFlag,
							outputFileFlag,
							batchFlag,
						},
						Description: `
	phase2 init --batch <size> --input <filepath> --output <filepath>

will generate a phase2 file with a phase1 input, should be used by
the first participant to generate the first file. A parameter "batch"
is required by circuit definition, which depends on the amount of
input message, please refer
https://github.com/bane-labs/zk-dkg/blob/v0.1.0/circuit/batch_encryption.go#L33`,
					},
					{
						Name:   "verify",
						Usage:  "Verify the phase2 file step forward",
						Action: verifyPhase2,
						Flags: []cli.Flag{
							inputFileFlag,
							outputFileFlag,
						},
						Description: `
	phase2 verify --input <filepath> --output <filepath>

will verify the contribute operation that takes place on the input
file to the output file, should be used before any further contribution
to the unverified output file.`,
					},
					{
						Name:   "contribute",
						Usage:  "Contribute to the phase2 MPC",
						Action: contributePhase2,
						Flags: []cli.Flag{
							inputFileFlag,
							outputFileFlag,
						},
						Description: `
	phase2 contribute --input <filepath> --output <filepath>

will generate a new phase2 file based on the input one, every
participant should do this only once and one by one, so that a
chain of this contribute operations realize a MPC.`,
					},
				},
			},
			{
				Name:        "contract",
				Usage:       "Commands about solidity contract",
				Description: ``,
				Subcommands: []*cli.Command{
					{
						Name:   "export",
						Usage:  "Export Solidity verification contracts based on MPC files",
						Action: exportContract,
						Flags: []cli.Flag{
							phase1FileFlag,
							phase2FileFlag,
							batchFlag,
							contractFileFlag,
						},
						Description: `
	contract export --batch <size> --phase1file <filepath> --phase2file <filepath>

will generate a Solidity verification contract file based on the
input MPC phase1 and phase2 files, the same parameter "batch" used
in "phase2 init" should also be provided, please refer
https://github.com/bane-labs/zk-dkg/blob/v0.1.0/circuit/batch_encryption.go#L33.`,
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

func exportContract(ctx *cli.Context) error {
	phase1FilePath := ctx.Path(phase1FileFlag.Name)
	if phase1FilePath == "" {
		return errors.New("invalid phase1 file path")
	}
	phase2FilePath := ctx.Path(phase2FileFlag.Name)
	if phase2FilePath == "" {
		return errors.New("invalid phase2 file path")
	}
	size := ctx.Int(batchFlag.Name)
	if size < 1 {
		return errors.New("batch size must be positive")
	}
	contractFilePath := ctx.Path(contractFileFlag.Name)
	if contractFilePath == "" {
		return errors.New("invalid contract file path")
	}
	// Generate node private key
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	// Computing public key
	fis := make([]fr_bls12381.Element, size)
	pubKeys := make([]*ecies.PublicKey, size)
	for i := 0; i < size; i++ {
		key, _ := ecies.GenerateKey(rand, crypto.S256(), nil)
		pubKeys[i] = &key.PublicKey
		var fi fr_bls12381.Element
		fi.SetRandom()
		fis[i] = fi
	}
	fisBytes, _, _, _, encryptedFis, _, _ := circuit.PrepareEncryptedKeyShares(pubKeys, fis)
	c := circuit.BatchEncryptionWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		Account:      make([]circuit.AccountConstraints[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], size),
		CommentsHash: make([]frontend.Variable, 32),
	}
	for i := 0; i < size; i++ {
		c.Account[i].PlainChunks = make([]frontend.Variable, len(fisBytes[i]))
		c.Account[i].CipherChunks = make([]frontend.Variable, len(encryptedFis[i]))
	}

	css, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
	if err != nil {
		return err
	}
	_, vk, err := helper.GetInitParamsFromExistedMPCSetUp(css, phase1FilePath, phase2FilePath)
	if err != nil {
		return err
	}
	helper.ExportContract(vk, contractFilePath)
	return nil
}

func initPhase1(ctx *cli.Context) error {
	path := ctx.Path(outputFileFlag.Name)
	if path == "" {
		path = DefaultPhase1FilePrefix + "1"
	}
	_, err := mpc.InitPhase1(path, uint64(math.Pow(2, 24)))
	if err != nil {
		return err
	}
	return nil
}

func verifyPhase1(ctx *cli.Context) error {
	path1 := ctx.Path(inputFileFlag.Name)
	if path1 == "" {
		return errors.New("inputFile path can not be nil")
	}
	path2 := ctx.Path(outputFileFlag.Name)
	if path2 == "" {
		return errors.New("outputFile path can not be nil")
	}
	_, err := mpc.VerifyPhase1(path1, path2)
	if err != nil {
		return err
	}
	fmt.Println("Phase1 verify : OK")
	return nil
}

func contributePhase1(ctx *cli.Context) error {
	inputPath := ctx.Path(inputFileFlag.Name)
	if inputPath == "" {
		return errors.New("inputFile1 path can not be nil")
	}
	outputPath := ctx.Path(outputFileFlag.Name)
	if outputPath == "" {
		return errors.New("outputFile path can not be nil")
	}
	_, err := mpc.ContributePhase1(inputPath, outputPath)
	if err != nil {
		return err
	}
	return nil
}

func getCommonSRS(ctx *cli.Context) error {
	inputPath := ctx.Path(inputFileFlag.Name)
	if inputPath == "" {
		return errors.New("inputFile1 path can not be nil")
	}
	outputPath := ctx.Path(outputFileFlag.Name)
	if outputPath == "" {
		return errors.New("outputFile path can not be nil")
	}
	_, err := mpc.Seal(inputPath, outputPath)
	if err != nil {
		return err
	}
	return nil
}

func initPhase2(ctx *cli.Context) error {
	inputPath := ctx.Path(inputFileFlag.Name)
	if inputPath == "" {
		return errors.New("inputFile path can not be nil")
	}
	outputpath := ctx.Path(outputFileFlag.Name)
	if outputpath == "" {
		outputpath = DefaultPhase2FilePrefix + "1"
	}
	size := ctx.Int(batchFlag.Name)
	if size < 1 {
		return errors.New("batch must be positive")
	}
	// Generate node private key
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	// Computing public key
	fis := make([]fr_bls12381.Element, size)
	pubKeys := make([]*ecies.PublicKey, size)
	for i := 0; i < size; i++ {
		key, _ := ecies.GenerateKey(rand, crypto.S256(), nil)
		pubKeys[i] = &key.PublicKey
		var fi fr_bls12381.Element
		fi.SetRandom()
		fis[i] = fi
	}
	fisBytes, _, _, _, encryptedFis, _, _ := circuit.PrepareEncryptedKeyShares(pubKeys, fis)
	c := circuit.BatchEncryptionWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		Account:      make([]circuit.AccountConstraints[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], size),
		CommentsHash: make([]frontend.Variable, 32),
	}
	for i := 0; i < size; i++ {
		c.Account[i].PlainChunks = make([]frontend.Variable, len(fisBytes[i]))
		c.Account[i].CipherChunks = make([]frontend.Variable, len(encryptedFis[i]))
	}

	css, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
	if err != nil {
		return err
	}
	_, _, _, err = mpc.InitPhase2(css, inputPath, outputpath)
	if err != nil {
		return err
	}
	return nil
}

func verifyPhase2(ctx *cli.Context) error {
	path1 := ctx.Path(inputFileFlag.Name)
	if path1 == "" {
		return errors.New("inputFile path can not be nil")
	}
	path2 := ctx.Path(outputFileFlag.Name)
	if path2 == "" {
		return errors.New("outputFile path can not be nil")
	}
	_, err := mpc.VerifyPhase2(path1, path2)
	if err != nil {
		return err
	}
	fmt.Println("phase2 verify pass")
	return nil
}

func contributePhase2(ctx *cli.Context) error {
	inputPath := ctx.Path(inputFileFlag.Name)
	if inputPath == "" {
		return errors.New("inputFile path can not be nil")
	}
	outputPath := ctx.Path(outputFileFlag.Name)
	if outputPath == "" {
		return errors.New("outputFile path can not be nil")
	}
	_, err := mpc.ContributePhase2(inputPath, outputPath)
	if err != nil {
		return err
	}
	return nil
}
