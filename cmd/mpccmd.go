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

	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"

	"github.com/bane-labs/zk-dkg/circuit"
	"github.com/bane-labs/zk-dkg/helper"
	"github.com/bane-labs/zk-dkg/mpc"
	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"

	"github.com/urfave/cli/v2"
)

const (
	DefaultInnerFilePrefix  = "inner_"
	DefaultPhase1FilePrefix = "phase1_"
	DefaultPhase2FilePrefix = "phase2_"
	DefaultOuterFilePrefix  = "outer_"
	DefaultCSSFilesPrefix   = "css_"
	DefaultCSSFileName      = "css"
	DefaultSRSFileName      = "srs"
	DefaultPKFileName       = "pk"
	DefaultVKFileName       = "vk"
	DefaultContractFileName = "verifier"
)

var (
	batchArray = [3]int{1, 2, 7}
	MaxBatch   = 7
)

var (
	// Flags for MPC contribution and verification
	inputFileFlag = &cli.PathFlag{
		Name:  "input",
		Usage: "The input file path of a MPC contribution",
	}
	outputFileFlag = &cli.PathFlag{
		Name:  "output",
		Usage: "The out file path of a MPC contribution",
	}
	// Flags for MPC sealing
	srsFileFlag = &cli.PathFlag{
		Name:  "srs",
		Usage: "The file path of a SRS",
	}
	innerCSSFileFlag = &cli.PathFlag{
		Name:  "inner-css",
		Usage: "The file path of a css of inner circuit",
	}
	outerCSSFileFlag = &cli.PathFlag{
		Name:  "outer-css",
		Usage: "The file path of a css of outer circuit",
	}
	// Flags for parameter export
	pkFileFlag = &cli.PathFlag{
		Name:  "provingkey",
		Usage: "The file path of a proving key",
	}
	vkFileFlag = &cli.PathFlag{
		Name:  "verifyingkey",
		Usage: "The file path of a verifying key",
	}
	// Flags for contract export
	contractFileFlag = &cli.PathFlag{
		Name:  "contract",
		Usage: "The output folder path of outer contract",
	}
)

func main() {
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:  "inner",
				Usage: "Deal with MPC for the inner circuit",
				Description: `
This batch of commands deal with the Groth16 MPC setup for the
inner circuit.`,
				Subcommands: []*cli.Command{
					{
						Name:  "phase1",
						Usage: "Deal with MPC phase1",
						Description: `
Phase1 commands deal the generation of Groth16 setup parameters,
should be performed before any ZK application deployed based on
this algorithm. The result can be used by any phase2.`,
						Subcommands: []*cli.Command{
							{
								Name:   "init",
								Usage:  "Generate init inner phase1 file",
								Action: initInnerPhase1,
								Flags: []cli.Flag{
									outputFileFlag,
								},
								Description: `
	inner phase1 init --output <filepath>

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
	inner phase1 verify --input <filepath> --output <filepath>

will verify the contribute operation that takes place on the
input file to the output file, should be used before any further
contribution to the unverified output file.`,
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
	inner phase1 contribute --input <filepath> --output <filepath>

will generate a new phase1 file based on the input one, every
participant should do this only once and one by one, so that a
chain of this contribute operations realize a MPC.`,
							},
							{
								Name:   "seal",
								Usage:  "Convert inner Phase1 data to common SRS",
								Action: sealInnerPhase1,
								Flags: []cli.Flag{
									inputFileFlag,
									srsFileFlag,
								},
								Description: `
	inner phase1 seal --input <phase1file> --srs <outputpath>

will seal a phase1 file to a common SRS, each participant can
execute this operation locally to verify that the correct public
SRS string is used in sealing.`,
							},
						},
					},
					{
						Name:  "phase2",
						Usage: "Deal with MPC phase2",
						Description: `
Phase2 commands deal the generation of circuit setup parameters,
should be performed before every ZK application deployed based on
phase1. The result can be used by this application repeatedly.`,
						Subcommands: []*cli.Command{
							{
								Name:   "init",
								Usage:  "Generate the first inner phase2 file",
								Action: initInnerPhase2,
								Flags: []cli.Flag{
									srsFileFlag,
									outputFileFlag,
									innerCSSFileFlag,
								},
								Description: `
	inner phase2 init --srs <inputpath> --output <filepath> --inner-css <outputpath>

will generate a phase2 file with a SRS file from phase1 as input,
should be used by the first participant to generate the first file.
An R1CS file will also be generated, which will be used in the
final phase2 sealing.`,
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
	inner phase2 verify --input <filepath> --output <filepath>

will verify the contribute operation that takes place on the input
file to the output file, should be used before any further
contribution to the unverified output file.`,
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
	inner phase2 contribute --input <filepath> --output <filepath>

will generate a new phase2 file based on the input one, every
participant should do this only once and one by one, so that a
chain of this contribute operations realize a MPC.`,
							},
						},
					},
					{
						Name:   "seal",
						Usage:  "Export the proving key and verifying key",
						Action: exportInnerSeal,
						Flags: []cli.Flag{
							srsFileFlag,
							innerCSSFileFlag,
							inputFileFlag,
							pkFileFlag,
							vkFileFlag,
						},
						Description: `
	inner seal --srs <inputpath> --inner-css <inputpath> --input <phase2file> --provingkey <outputpath> --verifyingkey <outputpath>

will generate a proving key file and a verifying key file based
on a MPC phase2, the SRS file and the R1CS file generated in the
previous steps.`,
					},
				},
			},
			{
				Name:  "outer",
				Usage: "Deal with MPC for the outer circuit",
				Description: `
This batch of commands deal with the Plonk MPC setup for the
outer circuit.`,
				Subcommands: []*cli.Command{
					{
						Name:   "init",
						Usage:  "Init outer SRS file for MPC",
						Action: initOuterSRS,
						Flags: []cli.Flag{
							innerCSSFileFlag,
							pkFileFlag,
							vkFileFlag,
							outputFileFlag,
							outerCSSFileFlag,
						},
						Description: `
	outer init --inner-css <inputpath> --provingkey <inputpath> --verifyingkey <inputpath> --output <filepath> --outer-css <filesprefix>

will generate a phase1 file without any input, should be used by
the first participant to generate the first file. The SRS file is
generated based on the maximum size of the outer circuit we may use.
A batch of css files will also be generated under the same prefix.`,
					},
					{
						Name:   "checkInit",
						Usage:  "Verify the initialization of an outer SRS file",
						Action: verifyInitOuterSRS,
						Flags: []cli.Flag{
							outerCSSFileFlag,
							outputFileFlag,
						},
						Description: `
	outer checkInit --outer-css <filesprefix> --output <filepath>

will verify the initialization that takes place on the inner
R1CS file to the output file, should be used before any further
contribution to the unverified output file. The R1CS file under
this prefix and ends with "7" will be used for verification.`,
					},
					{
						Name:   "verify",
						Usage:  "Verify the outer SRS file step forward",
						Action: verifyOuterSRS,
						Flags: []cli.Flag{
							outerCSSFileFlag,
							inputFileFlag,
							outputFileFlag,
						},
						Description: `
	outer verify --outer-css <filesprefix> --input <filepath> --output <filepath>

will verify the contribute operation that takes place on the
input file to the output file, should be used before any further
contribution to the unverified output file. The R1CS file under
this prefix and ends with "7" will be used for verification.`,
					},
					{
						Name:   "contribute",
						Usage:  "Contribute to the outer SRS MPC",
						Action: contributeOuterSRS,
						Flags: []cli.Flag{
							inputFileFlag,
							outputFileFlag,
							outerCSSFileFlag,
						},
						Description: `
	outer contribute --outer-css <filesprefix> --input <filepath> --output <filepath>

will generate a new phase1 file based on the input one, every
participant should do this only once and one by one, so that a
chain of this contribute operations realize a MPC. The R1CS
file under this prefix and ends with "7" will be used.`,
					},
					{
						Name:   "seal",
						Usage:  "Export the proving key and verifying key",
						Action: exportOuterSeal,
						Flags: []cli.Flag{
							outerCSSFileFlag,
							inputFileFlag,
							pkFileFlag,
							vkFileFlag,
							contractFileFlag,
						},
						Description: `
	outer seal --outer-css <filesprefix> --input <filepath> --provingkey <outputpath> --verifyingkey <outputpath> --contract <outputpath>

will export MPC data to a batch of proving keys, verifying keys
and Solidity verifier contracts, each participant can execute
this operation locally to verify that the correct public SRS
string is used.`,
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

// initInnerPhase1 initializes the initial inner phase1 file.
func initInnerPhase1(ctx *cli.Context) error {
	path := ctx.Path(outputFileFlag.Name)
	if path == "" {
		path = DefaultInnerFilePrefix + DefaultPhase1FilePrefix + "1"
	}
	p, err := mpc.InitGroth16Phase1(path, uint64(math.Pow(2, 21)))
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

// verifyInnerPhase1 verifies the inner phase1 contribution.
func verifyInnerPhase1(ctx *cli.Context) error {
	path1 := ctx.Path(inputFileFlag.Name)
	if path1 == "" {
		return errors.New("invalid inner phase1 path")
	}
	path2 := ctx.Path(outputFileFlag.Name)
	if path2 == "" {
		return errors.New("invalid inner phase1 path")
	}
	challenge, err := mpc.VerifyGroth16Phase1(path1, path2)
	if err != nil {
		return err
	}
	fmt.Println("InnerPhase1 verified, and the previous challenge is", hex.EncodeToString(challenge))
	return nil
}

// contributeInnerPhase1 contributes to the inner phase1 MPC.
func contributeInnerPhase1(ctx *cli.Context) error {
	inputPath := ctx.Path(inputFileFlag.Name)
	if inputPath == "" {
		return errors.New("invalid inner phase1 path")
	}
	outputPath := ctx.Path(outputFileFlag.Name)
	if outputPath == "" {
		outputPath = DefaultInnerFilePrefix + DefaultPhase1FilePrefix + "new"
	}
	p, err := mpc.ContributeGroth16Phase1(inputPath, outputPath)
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

// sealInnerPhase1 seals the inner phase1 contribution to SRS.
func sealInnerPhase1(ctx *cli.Context) error {
	inputPath := ctx.Path(inputFileFlag.Name)
	if inputPath == "" {
		return errors.New("invalid inner phase1 path")
	}
	outputPath := ctx.Path(srsFileFlag.Name)
	if outputPath == "" {
		outputPath = DefaultInnerFilePrefix + DefaultPhase1FilePrefix + DefaultSRSFileName
	}
	_, err := mpc.SealGroth16Phase1(inputPath, outputPath)
	if err != nil {
		return err
	}
	return nil
}

// initInnerPhase2 initializes the initial inner phase2 file.
func initInnerPhase2(ctx *cli.Context) error {
	inputPath := ctx.Path(srsFileFlag.Name)
	if inputPath == "" {
		return errors.New("invalid phase1 SRS path")
	}
	outputpath := ctx.Path(outputFileFlag.Name)
	if outputpath == "" {
		outputpath = DefaultInnerFilePrefix + DefaultPhase2FilePrefix + "1"
	}
	r1csPath := ctx.Path(innerCSSFileFlag.Name)
	if r1csPath == "" {
		r1csPath = DefaultInnerFilePrefix + DefaultCSSFileName
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
	innerCircuit := circuit.GetSingleKeyShareEncryptionCircuit(fisBytes[0], encryptedFis[0])
	css, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, innerCircuit)
	if err != nil {
		return err
	}
	_, _, p, err := mpc.InitGroth16Phase2(css, inputPath, outputpath)
	if err != nil {
		return err
	}
	sha := sha256.New()
	if _, err := p.WriteTo(sha); err != nil {
		panic(err)
	}
	fmt.Println("File challenge:", hex.EncodeToString(sha.Sum(nil)))
	helper.ExportCSS(css, r1csPath)
	return nil
}

// verifyInnerPhase2 verifies the inner phase2 contribution.
func verifyInnerPhase2(ctx *cli.Context) error {
	path1 := ctx.Path(inputFileFlag.Name)
	if path1 == "" {
		return errors.New("invalid inner phase2 path")
	}
	path2 := ctx.Path(outputFileFlag.Name)
	if path2 == "" {
		return errors.New("invalid inner phase2 path")
	}
	challenge, err := mpc.VerifyGroth16Phase2(path1, path2)
	if err != nil {
		return err
	}
	fmt.Println("Inner Phase2 verified, and the previous challenge is", hex.EncodeToString(challenge))
	return nil
}

// contributeInnerPhase2 contributes to the inner phase2 MPC.
func contributeInnerPhase2(ctx *cli.Context) error {
	inputPath := ctx.Path(inputFileFlag.Name)
	if inputPath == "" {
		return errors.New("invalid inner phase2 path")
	}
	outputPath := ctx.Path(outputFileFlag.Name)
	if outputPath == "" {
		outputPath = DefaultInnerFilePrefix + DefaultPhase2FilePrefix + "new"
	}
	p, err := mpc.ContributeGroth16Phase2(inputPath, outputPath)
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

// exportInnerSeal exports the inner proving key and verifying key.
func exportInnerSeal(ctx *cli.Context) error {
	srsPath := ctx.Path(srsFileFlag.Name)
	if srsPath == "" {
		return errors.New("invalid inner phase1 SRS path")
	}
	r1csPath := ctx.Path(innerCSSFileFlag.Name)
	if r1csPath == "" {
		return errors.New("invalid R1CS path")
	}
	phase2Path := ctx.Path(inputFileFlag.Name)
	if phase2Path == "" {
		return errors.New("invalid inner phase2 path")
	}
	innerPKPath := ctx.Path(pkFileFlag.Name)
	if innerPKPath == "" {
		innerPKPath = DefaultInnerFilePrefix + DefaultPKFileName
	}
	innerVKPath := ctx.Path(vkFileFlag.Name)
	if innerVKPath == "" {
		innerVKPath = DefaultInnerFilePrefix + DefaultVKFileName
	}

	css, err := helper.ReadCSS(r1csPath)
	if err != nil {
		return err
	}
	pk, vk, err := helper.GetKeysFromExistedGroth16SetUp(css, srsPath, phase2Path)
	if err != nil {
		return err
	}
	helper.ExportGroth16ProvingKey(pk, innerPKPath)
	helper.ExportGroth16VerifyingKey(vk, innerVKPath)
	return nil
}

// initOuterSRS initializes the first outer SRS file for Plonk MPC.
// It generates a batch of CSS files based on different verifications
// on different number of inner circuits.
func initOuterSRS(ctx *cli.Context) error {
	innerCSSPath := ctx.Path(innerCSSFileFlag.Name)
	if innerCSSPath == "" {
		return errors.New("invalid inner R1CS path")
	}
	innerPKPath := ctx.Path(pkFileFlag.Name)
	if innerPKPath == "" {
		return errors.New("invalid inner provingkey path")
	}
	innerVKPath := ctx.Path(vkFileFlag.Name)
	if innerVKPath == "" {
		return errors.New("invalid inner verifyingKey path")
	}

	outerSRSPath := ctx.Path(outputFileFlag.Name)
	if outerSRSPath == "" {
		outerSRSPath = DefaultOuterFilePrefix + DefaultSRSFileName
	}
	outerCSSPath := ctx.Path(outerCSSFileFlag.Name)
	if outerCSSPath == "" {
		outerCSSPath = DefaultOuterFilePrefix + DefaultCSSFileName
	}
	for i := 0; i < len(batchArray); i++ {
		batch := batchArray[i]
		innerCSS, err := helper.ReadCSS(innerCSSPath)
		if err != nil {
			return err
		}
		innerPK, err := helper.ReadGroth16ProvingKey(innerPKPath)
		if err != nil {
			return err
		}
		innerVK, err := helper.ReadGroth16VerifyingKey(innerVKPath)
		if err != nil {
			return err
		}
		innerCSSs := make([]constraint.ConstraintSystem, batch)
		innerPKs := make([]*groth16.ProvingKey, batch)
		innerVKs := make([]*groth16.VerifyingKey, batch)
		for i := 0; i < batch; i++ {
			innerCSSs[i] = innerCSS
			innerPKs[i] = innerPK
			innerVKs[i] = innerVK
		}
		outerCircuit := circuit.GetRecursionEncryptionCircuit(batch, innerCSSs, innerVKs)
		outerCSS, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, outerCircuit)
		if err != nil {
			return err
		}
		r1cs := outerCSS.(*cs.SparseR1CS)
		helper.ExportCSS(outerCSS, outerCSSPath+"_"+string(batchArray[i]))

		if i == MaxBatch {
			srsSize, _ := plonk.SRSSize(r1cs)
			p, err := mpc.InitPlonkSRS(outerSRSPath, srsSize)
			if err != nil {
				return err
			}
			sha := sha256.New()
			if _, err := p.WriteTo(sha); err != nil {
				panic(err)
			}
			fmt.Println("Outer SRS file challenge:", hex.EncodeToString(sha.Sum(nil)))
		}
	}

	return nil
}

// verifyInitOuterSRS verifies if the initialization of an outer
// SRS file is based on the correct SRS size of the outer circuit.
// The R1CS file for maximum batch size is used for verification.
func verifyInitOuterSRS(ctx *cli.Context) error {
	outerCSSPath := ctx.Path(outerCSSFileFlag.Name)
	if outerCSSPath == "" {
		return errors.New("invalid outer CSS prefix")
	}
	srsPath := ctx.Path(outputFileFlag.Name)
	if srsPath == "" {
		return errors.New("invalid outer SRS path")
	}
	css, err := helper.ReadCSS(outerCSSPath + "_" + string(MaxBatch))
	if err != nil {
		return err
	}
	r1cs := css.(*cs.SparseR1CS)
	srsSize, _ := plonk.SRSSize(r1cs)
	err = mpc.VerifyPlonkSRSInitialization(srsPath, srsSize)
	if err != nil {
		return err
	}
	fmt.Println("Initial outer SRS verified")
	return nil
}

// verifyOuterSRS verifies the outer SRS file is contributed
// based on the correct SRS size of the outer circuit and the
// specified previous outer SRS file.
// The R1CS file for maximum batch size is used for verification.
func verifyOuterSRS(ctx *cli.Context) error {
	outerCSSPath := ctx.Path(outerCSSFileFlag.Name)
	if outerCSSPath == "" {
		return errors.New("invalid outer CSS prefix")
	}
	prePath := ctx.Path(inputFileFlag.Name)
	if prePath == "" {
		return errors.New("invalid previous outer SRS path")
	}
	curPath := ctx.Path(outputFileFlag.Name)
	if curPath == "" {
		return errors.New("invalid current outer SRS path")
	}
	css, err := helper.ReadCSS(outerCSSPath + "_" + string(MaxBatch))
	if err != nil {
		return err
	}
	r1cs := css.(*cs.SparseR1CS)
	srsSize, _ := plonk.SRSSize(r1cs)
	err = mpc.VerifyPlonkSRS(prePath, curPath, srsSize)
	if err != nil {
		return err
	}
	fmt.Println("Current outer SRS verified")
	return nil
}

// contributeOuterSRS contributes to the outer SRS MPC.
// The R1CS file for maximum batch size is used for contribution.
func contributeOuterSRS(ctx *cli.Context) error {
	outerCSSPath := ctx.Path(outerCSSFileFlag.Name)
	if outerCSSPath == "" {
		return errors.New("invalid outer CSS prefix")
	}
	inputPath := ctx.Path(inputFileFlag.Name)
	if inputPath == "" {
		return errors.New("invalid previous outer SRS path")
	}
	outputPath := ctx.Path(outputFileFlag.Name)
	if outputPath == "" {
		outputPath = DefaultOuterFilePrefix + DefaultSRSFileName + "_new"
	}
	css, err := helper.ReadCSS(outerCSSPath + "_" + string(MaxBatch))
	if err != nil {
		return err
	}
	r1cs := css.(*cs.SparseR1CS)
	srsSize, _ := plonk.SRSSize(r1cs)

	p, err := mpc.ContributePlonkSRS(inputPath, outputPath, srsSize)
	if err != nil {
		return err
	}
	fmt.Println("SRS contributed")
	sha := sha256.New()
	if _, err := p.WriteTo(sha); err != nil {
		panic(err)
	}
	fmt.Println("File challenge:", hex.EncodeToString(sha.Sum(nil)))
	return nil
}

// exportOuterSeal exports the outer proving keys and verifying keys.
// The file number is determined by the different batch sizes we suppose.
func exportOuterSeal(ctx *cli.Context) error {
	outerCSSPath := ctx.Path(outerCSSFileFlag.Name)
	if outerCSSPath == "" {
		return errors.New("invalid outer CSS prefix")
	}
	inputPath := ctx.Path(inputFileFlag.Name)
	if inputPath == "" {
		return errors.New("invalid outer SRS path")
	}
	pkPath := ctx.Path(pkFileFlag.Name)
	if pkPath == "" {
		pkPath = DefaultOuterFilePrefix + DefaultPKFileName
	}
	vkPath := ctx.Path(vkFileFlag.Name)
	if vkPath == "" {
		vkPath = DefaultOuterFilePrefix + DefaultVKFileName
	}
	contractPath := ctx.Path(contractFileFlag.Name)
	if contractPath == "" {
		vkPath = DefaultOuterFilePrefix + DefaultContractFileName
	}
	for i := 0; i < len(batchArray); i++ {
		outerCSS, err := helper.ReadCSS(outerCSSPath + "_" + string(batchArray[i]))
		if err != nil {
			return err
		}
		pk, vk, err := helper.GetKeysFromExistedPlonkSetUp(outerCSS, inputPath)
		if err != nil {
			return err
		}
		helper.ExportPlonkProvingKey(pk, pkPath+"_"+string(batchArray[i]))
		helper.ExportPlonkVerifyingKey(vk, vkPath+"_"+string(batchArray[i]))
		helper.ExportContract(vk, contractPath+"_"+string(batchArray[i])+".sol")
	}
	return nil
}
