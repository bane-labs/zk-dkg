package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
)

const (
	DefaultPhase1FilePrefix = "Phase1_"
	DefaultPhase2FilePrefix = "Phase2_"
)

var (
	inputFileNameFlag = &cli.PathFlag{
		Name: "input",
	}
	outputFileNameFlag = &cli.PathFlag{
		Name: "output",
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
							inputFileNameFlag,
						},
						Description: ``,
					},
					{
						Name:   "contribute",
						Usage:  "",
						Action: contributePhase1,
						Flags: []cli.Flag{
							inputFileNameFlag,
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
							outputFileNameFlag,
						},
						Description: ``,
					},
					{
						Name:   "verify",
						Usage:  "",
						Action: verifyPhase2,
						Flags: []cli.Flag{
							inputFileNameFlag,
						},
						Description: ``,
					},
					{
						Name:   "contribute",
						Usage:  "",
						Action: contributePhase2,
						Flags: []cli.Flag{
							inputFileNameFlag,
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
	return nil
}

func verifyPhase1(ctx *cli.Context) error {
	path := ctx.Path(inputFileNameFlag.Name)
	if path == "" {

	}
	return nil
}

func contributePhase1(ctx *cli.Context) error {
	inputPath := ctx.Path(inputFileNameFlag.Name)
	if inputPath == "" {

	}
	outputPath := ctx.Path(outputFileNameFlag.Name)
	if outputPath == "" {

	}
	return nil
}

func initPhase2(ctx *cli.Context) error {
	path := ctx.Path(outputFileNameFlag.Name)
	if path == "" {

	}
	return nil
}

func verifyPhase2(ctx *cli.Context) error {
	path := ctx.Path(inputFileNameFlag.Name)
	if path == "" {

	}
	return nil
}

func contributePhase2(ctx *cli.Context) error {
	inputPath := ctx.Path(inputFileNameFlag.Name)
	if inputPath == "" {

	}
	outputPath := ctx.Path(outputFileNameFlag.Name)
	if outputPath == "" {

	}
	return nil
}
