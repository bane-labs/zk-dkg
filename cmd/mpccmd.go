package main

import (
	"errors"
	"fmt"
	"github.com/bane-labs/zk-dkg/circuit"
	"github.com/bane-labs/zk-dkg/mpc"
	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/urfave/cli/v2"
)

const (
	DefaultPhase1FilePrefix = "Phase1_"
	DefaultPhase2FilePrefix = "Phase2_"
)

var (
	inputFileNameFlag1 = &cli.PathFlag{
		Name: "input1",
	}
	inputFileNameFlag2 = &cli.PathFlag{
		Name: "input2",
	}
	outputFileNameFlag = &cli.PathFlag{
		Name: "output",
	}
	batchFlag = &cli.PathFlag{
		Name: "batch",
	}
)

func main() {
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:        "phase1",
				Usage:       "Deal with MPC phase1",
				Description: ``,
				Subcommands: []*cli.Command{
					{
						Name:   "init",
						Usage:  "",
						Action: initPhase1,
						Flags: []cli.Flag{
							outputFileNameFlag,
						},
						Description: ``,
					},
					{
						Name:   "verify",
						Usage:  "",
						Action: verifyPhase1,
						Flags: []cli.Flag{
							inputFileNameFlag1,
							inputFileNameFlag2,
						},
						Description: ``,
					},
					{
						Name:   "contribute",
						Usage:  "",
						Action: contributePhase1,
						Flags: []cli.Flag{
							inputFileNameFlag1,
							outputFileNameFlag,
						},
						Description: ``,
					},
				},
			},
			{
				Name:        "phase2",
				Usage:       "Deal with MPC phase2",
				Description: ``,
				Subcommands: []*cli.Command{
					{
						Name:   "init",
						Usage:  "",
						Action: initPhase2,
						Flags: []cli.Flag{
							inputFileNameFlag1,
							outputFileNameFlag,
							batchFlag,
						},
						Description: ``,
					},
					{
						Name:   "verify",
						Usage:  "",
						Action: verifyPhase2,
						Flags: []cli.Flag{
							inputFileNameFlag1,
							inputFileNameFlag2,
						},
						Description: ``,
					},
					{
						Name:   "contribute",
						Usage:  "",
						Action: contributePhase2,
						Flags: []cli.Flag{
							inputFileNameFlag1,
							outputFileNameFlag,
						},
						Description: ``,
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

func initPhase1(ctx *cli.Context) error {
	path := ctx.Path(outputFileNameFlag.Name)
	if path == "" {
		path = DefaultPhase1FilePrefix + "1"
	}
	_, err := mpc.InitPhase1(path, 24)
	if err != nil {
		return err
	}
	return nil
}

func verifyPhase1(ctx *cli.Context) error {
	path1 := ctx.Path(inputFileNameFlag1.Name)
	if path1 == "" {
		return errors.New("inputFile1 path can not be nil")
	}
	path2 := ctx.Path(inputFileNameFlag2.Name)
	if path2 == "" {
		return errors.New("inputFile2 path can not be nil")
	}
	_, err := mpc.VerifyPhase1(path1, path2)
	if err != nil {
		return err
	}
	fmt.Println("phase1 verify pass")
	return nil
}

func contributePhase1(ctx *cli.Context) error {
	inputPath := ctx.Path(inputFileNameFlag1.Name)
	if inputPath == "" {
		return errors.New("inputFile1 path can not be nil")
	}
	outputPath := ctx.Path(outputFileNameFlag.Name)
	if outputPath == "" {
		return errors.New("outputFile path can not be nil")
	}
	_, _, err := mpc.ContributePhase1(inputPath, outputPath)
	if err != nil {
		return err
	}
	return nil
}

func initPhase2(ctx *cli.Context) error {
	inputPath := ctx.Path(inputFileNameFlag1.Name)
	if inputPath == "" {
		return errors.New("inputFile1 path can not be nil")
	}
	outputpath := ctx.Path(outputFileNameFlag.Name)
	if outputpath == "" {
		outputpath = DefaultPhase2FilePrefix + "1"
	}
	batch := ctx.Path(batchFlag.Name)
	if outputpath == "" {
		outputpath = DefaultPhase2FilePrefix + "1"
	}
	size, err := strconv.Atoi(batch)
	if err != nil {
		return err
	}
	// Generate node private key
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	// Computing public key
	fis := make([]fr_bls12381.Element, size)
	pubKeys := make([]ecies.PublicKey, size)
	for i := 0; i < size; i++ {
		key, _ := ecies.GenerateKey(rand, crypto.S256(), nil)
		pubKeys[i] = key.PublicKey
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
	path1 := ctx.Path(inputFileNameFlag1.Name)
	if path1 == "" {
		return errors.New("inputFile1 path can not be nil")
	}
	path2 := ctx.Path(inputFileNameFlag2.Name)
	if path2 == "" {
		return errors.New("inputFile2 path can not be nil")
	}
	_, err := mpc.VerifyPhase2(path1, path2)
	if err != nil {
		return err
	}
	fmt.Println("phase2 verify pass")
	return nil
}

func contributePhase2(ctx *cli.Context) error {
	inputPath := ctx.Path(inputFileNameFlag1.Name)
	if inputPath == "" {
		return errors.New("inputFile1 path can not be nil")
	}
	outputPath := ctx.Path(outputFileNameFlag.Name)
	if outputPath == "" {
		return errors.New("outputFile path can not be nil")
	}
	_, _, err := mpc.ContributePhase2(inputPath, outputPath)
	if err != nil {
		return err
	}
	return nil
}
