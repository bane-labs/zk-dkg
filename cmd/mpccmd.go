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

	"github.com/bane-labs/zk-dkg/circuit"
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
	phase1FileFlag = &cli.PathFlag{
		Name:  "phase1file",
		Usage: "The input file path of a phase1 contribution file",
	}
	phase2FileFlag = &cli.PathFlag{
		Name:  "phase2file",
		Usage: "The input file path of a phase2 contribution file",
	}
	srsFileFlag = &cli.PathFlag{
		Name:  "srsfile",
		Usage: "The input file path of a phase1 SRS file",
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
	contractFileFlag = &cli.PathFlag{
		Name:  "contract",
		Usage: "The out file path of contract exportation",
		Value: "Verifier.sol",
	}
	provingKeyFileFlag = &cli.PathFlag{
		Name:  "provingkey",
		Usage: "The out file path of proving key",
		Value: "ProvingKey",
	}
	verifyingKeyFileFlag = &cli.PathFlag{
		Name:  "verifyingkey",
		Usage: "The out file path of verifying key",
		Value: "VerifyingKey",
	}
	r1csFileFlag = &cli.PathFlag{
		Name:  "r1cs",
		Usage: "The out file path of r1cs",
		Value: "R1CS",
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
							phase1FileFlag,
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
						Usage:  "Contribute to the phase1 MPC",
						Action: contributePhase1,
						Flags: []cli.Flag{
							phase1FileFlag,
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
						Usage:  "Convert Phase1 data to common SRS",
						Action: sealPhase1,
						Flags: []cli.Flag{
							phase1FileFlag,
							outputFileFlag,
						},
						Description: `
	phase1 seal --phase1file <filepath> --output <filepath>

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
							srsFileFlag,
							outputFileFlag,
							batchFlag,
						},
						Description: `
	phase2 init --batch <size> --srsfile <filepath> --output <filepath>

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
							phase2FileFlag,
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
						Usage:  "Contribute to the phase2 MPC",
						Action: contributePhase2,
						Flags: []cli.Flag{
							phase2FileFlag,
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
				Name:   "seal",
				Usage:  "Export the proving key, verifying key and the verifier contract",
				Action: exportSeal,
				Flags: []cli.Flag{
					srsFileFlag,
					phase2FileFlag,
					batchFlag,
					contractFileFlag,
					provingKeyFileFlag,
					verifyingKeyFileFlag,
					r1csFileFlag,
				},
				Description: `
	seal --batch <size> --srsfile <filepath> --phase2file <filepath> --contract <filepath> --provingkey <filepath> --verifyingkey <filepath> --r1cs <filepath>

will generate a proving key file, a verifying key file, and a
Solidity verifier contract based on the input MPC phase1 and
phase2 files, the same parameter "batch" used in "phase2 init"
should also be provided, please refer
https://github.com/bane-labs/zk-dkg/blob/v0.1.0/circuit/batch_encryption.go#L33.`,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func exportSeal(ctx *cli.Context) error {
	srsFilePath := ctx.Path(srsFileFlag.Name)
	if srsFilePath == "" {
		return errors.New("invalid phase1 SRS file path")
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
	provingKeyFilePath := ctx.Path(provingKeyFileFlag.Name)
	if provingKeyFilePath == "" {
		return errors.New("invalid provingkey file path")
	}
	verifyingKeyFilePath := ctx.Path(verifyingKeyFileFlag.Name)
	if verifyingKeyFilePath == "" {
		return errors.New("invalid verifyingkey file path")
	}
	r1csFilePath := ctx.Path(r1csFileFlag.Name)
	if r1csFilePath == "" {
		return errors.New("invalid r1cs file path")
	}
	// Generate node private key
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	// Computing public key
	fis := make([]*fr_bls12381.Element, size)
	pubKeys := make([]*ecies.PublicKey, size)
	for i := 0; i < size; i++ {
		key, _ := ecies.GenerateKey(rand, crypto.S256(), nil)
		pubKeys[i] = &key.PublicKey
		fi, err := new(fr_bls12381.Element).SetRandom()
		if err != nil {
			return err
		}
		fis[i] = fi
	}
	_, _, _, encryptedFis, _, _, err := circuit.PrepareEncryptedKeyShares(pubKeys, fis)
	if err != nil {
		return err
	}
	c := circuit.BatchEncryptionWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		Parameters: make([]circuit.ECIESParameters[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], size),
		SumHash:    make([]frontend.Variable, 32),
	}
	for i := 0; i < size; i++ {
		c.Parameters[i].CipherChunks = make([]frontend.Variable, len(encryptedFis[i]))
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
	if err != nil {
		return err
	}
	pk, vk, err := mpc.GetInitParamsFromExistedMPCSetUp(ccs, srsFilePath, phase2FilePath)
	if err != nil {
		return err
	}
	err = mpc.ExportContract(vk, contractFilePath)
	if err != nil {
		return err
	}
	err = mpc.ExportProvingKey(pk, provingKeyFilePath)
	if err != nil {
		return err
	}
	err = mpc.ExportVerifyingKey(vk, verifyingKeyFilePath)
	if err != nil {
		return err
	}
	err = mpc.ExportCCS(ccs, r1csFilePath)
	if err != nil {
		return err
	}
	return nil
}

func initPhase1(ctx *cli.Context) error {
	path := ctx.Path(outputFileFlag.Name)
	if path == "" {
		path = DefaultPhase1FilePrefix + "1"
	}
	p, err := mpc.InitPhase1(path, uint64(math.Pow(2, 24)))
	if err != nil {
		return err
	}
	sha := sha256.New()
	if _, err := p.WriteTo(sha); err != nil {
		return err
	}
	fmt.Println("File challenge:", hex.EncodeToString(sha.Sum(nil)))
	return nil
}

func verifyPhase1(ctx *cli.Context) error {
	path1 := ctx.Path(phase1FileFlag.Name)
	if path1 == "" {
		return errors.New("invalid phase1 file path")
	}
	path2 := ctx.Path(outputFileFlag.Name)
	if path2 == "" {
		return errors.New("invalid output file path")
	}
	challenge, err := mpc.VerifyPhase1(path1, path2)
	if err != nil {
		return err
	}
	fmt.Println("Phase1 verified, and the previous challenge is", hex.EncodeToString(challenge))
	return nil
}

func contributePhase1(ctx *cli.Context) error {
	inputPath := ctx.Path(phase1FileFlag.Name)
	if inputPath == "" {
		return errors.New("invalid phase1 file path")
	}
	outputPath := ctx.Path(outputFileFlag.Name)
	if outputPath == "" {
		return errors.New("invalid output file path")
	}
	p, err := mpc.ContributePhase1(inputPath, outputPath)
	if err != nil {
		return err
	}
	fmt.Println("Contributed to:", hex.EncodeToString(p.Challenge))
	sha := sha256.New()
	if _, err := p.WriteTo(sha); err != nil {
		return err
	}
	fmt.Println("File challenge:", hex.EncodeToString(sha.Sum(nil)))
	return nil
}

func sealPhase1(ctx *cli.Context) error {
	inputPath := ctx.Path(phase1FileFlag.Name)
	if inputPath == "" {
		return errors.New("invalid phase1 file path")
	}
	outputPath := ctx.Path(outputFileFlag.Name)
	if outputPath == "" {
		return errors.New("invalid output file path")
	}
	_, err := mpc.Seal(inputPath, outputPath)
	if err != nil {
		return err
	}
	return nil
}

func initPhase2(ctx *cli.Context) error {
	inputPath := ctx.Path(srsFileFlag.Name)
	if inputPath == "" {
		return errors.New("invalid phase1 SRS file path")
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
	fis := make([]*fr_bls12381.Element, size)
	pubKeys := make([]*ecies.PublicKey, size)
	for i := 0; i < size; i++ {
		key, _ := ecies.GenerateKey(rand, crypto.S256(), nil)
		pubKeys[i] = &key.PublicKey
		fi, err := new(fr_bls12381.Element).SetRandom()
		if err != nil {
			return err
		}
		fis[i] = fi
	}
	_, _, _, encryptedFis, _, _, err := circuit.PrepareEncryptedKeyShares(pubKeys, fis)
	if err != nil {
		return err
	}
	c := circuit.BatchEncryptionWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		Parameters: make([]circuit.ECIESParameters[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], size),
		SumHash:    make([]frontend.Variable, 32),
	}
	for i := 0; i < size; i++ {
		c.Parameters[i].CipherChunks = make([]frontend.Variable, len(encryptedFis[i]))
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
	if err != nil {
		return err
	}
	_, _, p, err := mpc.InitPhase2(ccs, inputPath, outputpath)
	if err != nil {
		return err
	}
	sha := sha256.New()
	if _, err := p.WriteTo(sha); err != nil {
		return err
	}
	fmt.Println("File challenge:", hex.EncodeToString(sha.Sum(nil)))
	return nil
}

func verifyPhase2(ctx *cli.Context) error {
	path1 := ctx.Path(phase2FileFlag.Name)
	if path1 == "" {
		return errors.New("invalid phase2 file path")
	}
	path2 := ctx.Path(outputFileFlag.Name)
	if path2 == "" {
		return errors.New("invalid output file path")
	}
	challenge, err := mpc.VerifyPhase2(path1, path2)
	if err != nil {
		return err
	}
	fmt.Println("Phase2 verified, and the previous challenge is", hex.EncodeToString(challenge))
	return nil
}

func contributePhase2(ctx *cli.Context) error {
	inputPath := ctx.Path(phase2FileFlag.Name)
	if inputPath == "" {
		return errors.New("invalid phase2 file path")
	}
	outputPath := ctx.Path(outputFileFlag.Name)
	if outputPath == "" {
		return errors.New("invalid output file path")
	}
	p, err := mpc.ContributePhase2(inputPath, outputPath)
	if err != nil {
		return err
	}
	fmt.Println("Contributed to:", hex.EncodeToString(p.Challenge))
	sha := sha256.New()
	if _, err := p.WriteTo(sha); err != nil {
		return err
	}
	fmt.Println("File challenge:", hex.EncodeToString(sha.Sum(nil)))
	return nil
}
