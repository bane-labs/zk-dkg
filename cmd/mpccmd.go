package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/bane-labs/zk-dkg/circuit"
	"github.com/bane-labs/zk-dkg/helper"
	"github.com/bane-labs/zk-dkg/mpc"
	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/urfave/cli/v2"
)

const (
	DefaultSRSFilePrefix    = "srs_"
	DefaultInnerFilePrefix  = "inner_"
	DefaultOuterFilePrefix  = "outer_"
	DefaultCCSFilesPrefix   = "ccs_"
	DefaultPKFilePrefix     = "pk_"
	DefaultVKFilePrefix     = "vk_"
	DefaultCCSFileName      = "ccs"
	DefaultSRSFileName      = "srs"
	DefaultPKFileName       = "pk"
	DefaultVKFileName       = "vk"
	DefaultContractFileName = "verifier.sol"
)

var (
	InnerVKIDs = []int{1, 2, 7}
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
	innerCCSFileFlag = &cli.PathFlag{
		Name:  "inner-ccs",
		Usage: "The file path of a ccs of inner circuit",
	}
	outerCCSFileFlag = &cli.PathFlag{
		Name:  "outer-ccs",
		Usage: "The file path of a ccs of outer circuit",
	}
	beaconFlag = &cli.StringFlag{
		Name:  "beacon",
		Usage: "A random beacon of moderate entropy evaluated than the latest contribution",
	}
	// Flags for parameter export
	innerPkFileFlag = &cli.PathFlag{
		Name:  "inner-pk",
		Usage: "The file path of a proving key",
	}
	innerVkFileFlag = &cli.PathFlag{
		Name:  "inner-vk",
		Usage: "The file path of a verifying key",
	}
	outerPkFileFlag = &cli.PathFlag{
		Name:  "outer-pk",
		Usage: "The file path of a proving key",
	}
	outerVkFileFlag = &cli.PathFlag{
		Name:  "outer-vk",
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
				Name:  "CommonSRS",
				Usage: "Deal with MPC for the common SRS",
				Description: `
This batch of commands deal with the Plonk MPC setup for the common SRS.`,
				Subcommands: []*cli.Command{
					{
						Name:   "init",
						Usage:  "Init common SRS file for MPC",
						Action: initPlonkSRS,
						Flags: []cli.Flag{
							innerCCSFileFlag,
							srsFileFlag,
						},
						Description: `
	CommonSRS init --inner-ccs <filepath> --srs <filepath>

will generate a srs file without any input, should be used by
the first participant to generate the first file. The SRS file is
generated based on the maximum size of the inner circuit we may use.`,
					},
					{
						Name:   "checkInit",
						Usage:  "Verify the initialization of an common SRS file",
						Action: verifyInitPlonkSRS,
						Flags: []cli.Flag{
							innerCCSFileFlag,
							srsFileFlag,
						},
						Description: `
	CommonSRS checkInit --inner-ccs <filepath> --srs <filepath>

will verify the initialization that takes place on the inner
ccs file to the srs file, should be used before any further
contribution to the unverified output file.`,
					},
					{
						Name:   "verify",
						Usage:  "Verify the common SRS file step forward",
						Action: verifyPlonkSRS,
						Flags: []cli.Flag{
							innerCCSFileFlag,
							inputFileFlag,
							outputFileFlag,
						},
						Description: `
	CommonSRS verify --inner-ccs <filepath> --input <filepath> --output <filepath>

will verify the contribute operation that takes place on the
input file to the output file, should be used before any further
contribution to the unverified output file.`,
					},
					{
						Name:   "contribute",
						Usage:  "Contribute to the common SRS MPC",
						Action: contributePlonkSRS,
						Flags: []cli.Flag{
							innerCCSFileFlag,
							inputFileFlag,
							outputFileFlag,
						},
						Description: `
	CommonSRS contribute --inner-ccs <filepath> --input <filepath> --output <filepath>

will generate a new srs file based on the input one, every
participant should do this only once and one by one, so that a
chain of this contribute operations realize a MPC. `,
					},
				},
			},
			{
				Name:  "export",
				Usage: "Export related files with MPC for the common SRS",
				Description: `
This batch of commands deal with the Plonk MPC setup for the common SRS.`,
				Subcommands: []*cli.Command{
					{
						Name:   "innerCircuit",
						Usage:  "Export inner circuit ccs files",
						Action: exportInnerCircuit,
						Flags: []cli.Flag{
							innerCCSFileFlag,
						},
						Description: `
	export innerCircuit --inner-ccs <filesprefix>

will export inner circuit data to a batch of ccs files, each participant can execute
this operation locally to verify that the correct circuit is used.`,
					},
					{
						Name:   "innerSeal",
						Usage:  "Export inner circuit proving keys and verifying keys",
						Action: exportInnerSeal,
						Flags: []cli.Flag{
							srsFileFlag,
							innerCCSFileFlag,
							beaconFlag,
							innerPkFileFlag,
							innerVkFileFlag,
						},
						Description: `
	export innerSeal --srs <filepath> --beacon <string> --inner-ccs <filesprefix> --inner-pk <outputpath> --inner-vk <outputpath>

will export inner circuit data to a batch of proving keys, verifying keys, each participant can execute
this operation locally to verify that the correct circuit pk and vk is used.`,
					},
					{
						Name:   "outerSeal",
						Usage:  "Export outer circuit ccs,proving key and verifying key",
						Action: exportOuterSeal,
						Flags: []cli.Flag{
							srsFileFlag,
							innerCCSFileFlag,
							innerPkFileFlag,
							innerVkFileFlag,
							outerCCSFileFlag,
							beaconFlag,
							outerPkFileFlag,
							outerVkFileFlag,
							contractFileFlag,
						},
						Description: `
	export outerSeal --srs <filepath>  --beacon <string> --inner-ccs <filesprefix> --inner-pk <filesprefix> --inner-vk <filesprefix> --outer-ccs <outputpath> --outer-pk <outputpath> --outer-vk <outputpath> --contract <outputpath>

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
		_, err := fmt.Fprintln(os.Stderr, err)
		if err != nil {
			return
		}
		os.Exit(1)
	}
}

func initPlonkSRS(ctx *cli.Context) error {
	MaxSizeCCSPath := ctx.Path(innerCCSFileFlag.Name)
	if MaxSizeCCSPath == "" {
		return errors.New("invalid ccs path")
	}

	srsPath := ctx.Path(srsFileFlag.Name)
	if srsPath == "" {
		srsPath = DefaultSRSFilePrefix + strconv.Itoa(1)
	}
	MaxSizeCCS, err := helper.ReadCCS(MaxSizeCCSPath)
	if err != nil {
		return err
	}
	r1CS := MaxSizeCCS.(*cs.SparseR1CS)
	srsSize, _ := plonk.SRSSize(r1CS)
	p, err := mpc.InitPlonkSRS(srsPath, srsSize)
	if err != nil {
		return err
	}
	sha := sha256.New()
	if _, err := p.WriteTo(sha); err != nil {
		return err
	}
	fmt.Println("SRS file challenge:", hex.EncodeToString(sha.Sum(nil)))
	return nil
}

// verifyInitOuterSRS verifies if the initialization of an outer
// SRS file is based on the correct SRS size of the outer circuit.
// The R1CS file for maximum batch size is used for verification.
func verifyInitPlonkSRS(ctx *cli.Context) error {
	MaxSizeCCSPath := ctx.Path(innerCCSFileFlag.Name)
	if MaxSizeCCSPath == "" {
		return errors.New("invalid ccs path")
	}
	srsPath := ctx.Path(srsFileFlag.Name)
	if srsPath == "" {
		return errors.New("invalid outer SRS path")
	}
	ccs, err := helper.ReadCCS(MaxSizeCCSPath)
	if err != nil {
		return err
	}
	r1CS := ccs.(*cs.SparseR1CS)
	srsSize, _ := plonk.SRSSize(r1CS)
	err = mpc.VerifyPlonkSRSInitialization(srsPath, srsSize)
	if err != nil {
		return err
	}
	fmt.Println("Initial SRS verified")
	return nil
}

// verifyOuterSRS verifies the outer SRS file is contributed
// based on the correct SRS size of the outer circuit and the
// specified previous outer SRS file.
// The R1CS file for maximum batch size is used for verification.
func verifyPlonkSRS(ctx *cli.Context) error {
	MaxSizeCCSPath := ctx.Path(innerCCSFileFlag.Name)
	if MaxSizeCCSPath == "" {
		return errors.New("invalid inner R1CS path")
	}
	prePath := ctx.Path(inputFileFlag.Name)
	if prePath == "" {
		return errors.New("invalid previous outer SRS path")
	}
	curPath := ctx.Path(outputFileFlag.Name)
	if curPath == "" {
		return errors.New("invalid current outer SRS path")
	}
	ccs, err := helper.ReadCCS(MaxSizeCCSPath)
	if err != nil {
		return err
	}
	r1CS := ccs.(*cs.SparseR1CS)
	srsSize, _ := plonk.SRSSize(r1CS)
	err = mpc.VerifyPlonkSRS(prePath, curPath, srsSize)
	if err != nil {
		return err
	}
	fmt.Println("Current outer SRS verified")
	return nil
}

// contributeOuterSRS contributes to the outer SRS MPC.
// The R1CS file for maximum batch size is used for contribution.
func contributePlonkSRS(ctx *cli.Context) error {
	MaxSizeCCSPath := ctx.Path(innerCCSFileFlag.Name)
	if MaxSizeCCSPath == "" {
		return errors.New("invalid inner R1CS path")
	}
	inputPath := ctx.Path(inputFileFlag.Name)
	if inputPath == "" {
		return errors.New("invalid previous outer SRS path")
	}
	outputPath := ctx.Path(outputFileFlag.Name)
	if outputPath == "" {
		outputPath = DefaultOuterFilePrefix + DefaultSRSFileName + "_new"
	}
	ccs, err := helper.ReadCCS(MaxSizeCCSPath)
	if err != nil {
		return err
	}
	r1CS := ccs.(*cs.SparseR1CS)
	srsSize, _ := plonk.SRSSize(r1CS)

	p, err := mpc.ContributePlonkSRS(inputPath, outputPath, srsSize)
	if err != nil {
		return err
	}
	fmt.Println("SRS contributed")
	sha := sha256.New()
	if _, err := p.WriteTo(sha); err != nil {
		return err
	}
	fmt.Println("File challenge:", hex.EncodeToString(sha.Sum(nil)))
	return nil
}

func exportInnerCircuit(ctx *cli.Context) error {
	innerCCSPath := ctx.Path(innerCCSFileFlag.Name)
	if innerCCSPath == "" {
		innerCCSPath = DefaultInnerFilePrefix + DefaultCCSFilesPrefix
	}
	for index := 0; index < len(InnerVKIDs); index++ {
		batch := InnerVKIDs[index]
		// Generate node private key
		source := rand.NewSource(time.Now().UnixNano())
		r := rand.New(source)
		// Computing public key
		fis := make([]*fr_bls12381.Element, batch)
		pubKeys := make([]*ecies.PublicKey, batch)
		for i := 0; i < batch; i++ {
			key, _ := ecies.GenerateKey(r, crypto.S256(), nil)
			pubKeys[i] = &key.PublicKey
			fi := new(fr_bls12381.Element)
			_, err := fi.SetRandom()
			if err != nil {
				return err
			}
			fis[i] = fi
		}
		_, _, encryptedFis, _, err := circuit.PrepareEncryptedKeyShares(pubKeys, fis)
		if err != nil {
			return err
		}
		innerCircuit := circuit.GetBatchEncryptionCircuit(encryptedFis)
		innerCCS, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, innerCircuit)
		if err != nil {
			return err
		}
		err = mpc.ExportCCS(innerCCS, innerCCSPath+strconv.Itoa(batch))
		if err != nil {
			return err
		}
	}
	return nil
}

// exportInnerSeal exports the inner proving key and verifying key.
func exportInnerSeal(ctx *cli.Context) error {
	srsPath := ctx.Path(srsFileFlag.Name)
	if srsPath == "" {
		return errors.New("invalid inner phase1 SRS path")
	}
	beaconChallenge := ctx.String(beaconFlag.Name)
	if beaconChallenge == "" {
		return errors.New("invalid beacon challenge")
	}
	innerCCSPath := ctx.Path(innerCCSFileFlag.Name)
	if innerCCSPath == "" {
		return errors.New("invalid R1CS path")
	}
	innerPKPath := ctx.Path(innerPkFileFlag.Name)
	if innerPKPath == "" {
		innerPKPath = DefaultInnerFilePrefix + DefaultPKFilePrefix
	}
	innerVKPath := ctx.Path(innerVkFileFlag.Name)
	if innerVKPath == "" {
		innerVKPath = DefaultInnerFilePrefix + DefaultVKFilePrefix
	}

	for i := 0; i < len(InnerVKIDs); i++ {
		innerCCS, err := helper.ReadCCS(innerCCSPath + strconv.Itoa(InnerVKIDs[i]))
		if err != nil {
			return err
		}
		pk, vk, err := mpc.SealKeysFromExistedPlonkSetUp(innerCCS, srsPath, beaconChallenge)
		if err != nil {
			return err
		}
		err = mpc.ExportPlonkProvingKey(pk, innerPKPath+strconv.Itoa(InnerVKIDs[i]))
		if err != nil {
			return err
		}
		err = mpc.ExportPlonkVerifyingKey(vk, innerVKPath+strconv.Itoa(InnerVKIDs[i]))
		if err != nil {
			return err
		}
	}
	return nil
}

// exportOuterSeal exports the outer proving keys and verifying keys.
// The file number is determined by the different batch sizes we suppose.
func exportOuterSeal(ctx *cli.Context) error {
	srsPath := ctx.Path(srsFileFlag.Name)
	if srsPath == "" {
		return errors.New("invalid common SRS path")
	}
	beaconChallenge := ctx.String(beaconFlag.Name)
	if beaconChallenge == "" {
		return errors.New("invalid beacon challenge")
	}
	innerCCSPath := ctx.Path(innerCCSFileFlag.Name)
	if innerCCSPath == "" {
		return errors.New("invalid inner CCS prefix")
	}
	innerPKPath := ctx.Path(innerPkFileFlag.Name)
	if innerPKPath == "" {
		return errors.New("invalid inner pk prefix")
	}
	innerVKPath := ctx.Path(innerVkFileFlag.Name)
	if innerVKPath == "" {
		return errors.New("invalid inner vk prefix")
	}

	outerCCSPath := ctx.Path(outerCCSFileFlag.Name)
	if outerCCSPath == "" {
		outerCCSPath = DefaultOuterFilePrefix + DefaultCCSFileName
	}
	outerPKPath := ctx.Path(outerPkFileFlag.Name)
	if outerPKPath == "" {
		outerPKPath = DefaultOuterFilePrefix + DefaultPKFileName
	}
	outerVKPath := ctx.Path(outerVkFileFlag.Name)
	if outerVKPath == "" {
		outerVKPath = DefaultOuterFilePrefix + DefaultVKFileName
	}

	contractPath := ctx.Path(contractFileFlag.Name)
	if contractPath == "" {
		contractPath = DefaultOuterFilePrefix + DefaultContractFileName
	}

	innerCCSs := make([]constraint.ConstraintSystem, len(InnerVKIDs))
	innerPKs := make([]plonk.ProvingKey, len(InnerVKIDs))
	innerVKs := make([]plonk.VerifyingKey, len(InnerVKIDs))
	for i := 0; i < len(InnerVKIDs); i++ {
		innerCCS, err := helper.ReadCCS(innerCCSPath + strconv.Itoa(InnerVKIDs[i]))
		if err != nil {
			return err
		}
		innerPK, err := helper.ReadPlonkProvingKey(innerPKPath+strconv.Itoa(InnerVKIDs[i]), ecc.BN254)
		if err != nil {
			return err
		}
		innerVK, err := helper.ReadPlonkVerifyingKey(innerVKPath+strconv.Itoa(InnerVKIDs[i]), ecc.BN254)
		if err != nil {
			return err
		}
		innerCCSs[i] = innerCCS
		innerPKs[i] = innerPK
		innerVKs[i] = innerVK
	}
	nbPublic, nbCommitment := innerCCSs[0].GetNbPublicVariables(), len(innerCCSs[0].GetCommitments().CommitmentIndexes())
	for i := 0; i < len(innerCCSs); i++ {
		if innerCCSs[i].GetNbPublicVariables() != nbPublic || len(innerCCSs[i].GetCommitments().CommitmentIndexes()) != nbCommitment {
			return fmt.Errorf("all inner ccs should have the same len(public) and len(commitments)")
		}
	}
	outerCircuit, err := circuit.GetRecursionEncryptionCircuit(nbPublic, nbCommitment, innerVKs)
	if err != nil {
		return err
	}
	outerCCS, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, outerCircuit)
	if err != nil {
		return err
	}
	pk, vk, err := mpc.SealKeysFromExistedPlonkSetUp(outerCCS, srsPath, beaconChallenge)
	if err != nil {
		return err
	}
	err = mpc.ExportCCS(outerCCS, outerCCSPath)
	if err != nil {
		return err
	}
	err = mpc.ExportPlonkProvingKey(pk, outerPKPath)
	if err != nil {
		return err
	}
	err = mpc.ExportPlonkVerifyingKey(vk, outerVKPath)
	if err != nil {
		return err
	}
	err = mpc.ExportContract(vk, contractPath)
	if err != nil {
		return err
	}
	return nil
}
