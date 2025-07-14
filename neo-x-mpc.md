# Neo X MPC

After the audit and release of `zk-dkg`, we are going to perform a Groth16 MPC ceremony for Neo X Mainnet/Testnet DKG verification circuits.

Here is the introduction about how to use this library and `neofs` to compute and share MPC files.

We have two different `Phase1` and `Phase2` to execute step by step.

## Phase1

In this phase, we compute the Groth16 setup that can be used by any Neo X circuit, although the FFT domain size is very large and maybe not suitable for everyone.

1. Download the `zk-dkg` source code through `git clone https://github.com/bane-labs/zk-dkg.git`;

2. In the `/cmd` directory, the first contributor should run `go run mpccmd.go phase1 init --output <phase1 file path>` to create the first Phase1 file, the FFT domain size is set to `2^24` by default. You will get the first Phase1 file with its file challenge logged in the command line;

3. Following contributors should then compute based on existed Phase1 files one by one;

    i) Download the latest Phase1 file as your source file;
    
    ii) (Optional) If you are not the first or second contributor, you can run `go run mpccmd.go phase1 verify --phase1file <prev phase1 file path> --output <curr phase1 file path>` to check whether the Phase1 file you download is computed based on the correct source file;

    iii) (Optional) If you don't trust and want to verify the whole chain of MPC computation, then you need to download all Phase1 files before you, and use `go run mpccmd.go phase1 verify` to check one by one;

    iv) Run `go run mpccmd.go phase1 contribute --phase1file <prev phase1 file path> --output <curr phase1 file path>` in the `/cmd` directory, to contribute to your source file, and get a new Phase1 file;

    v) (Optional) If you are not the first contributor, you can run `go run mpccmd.go phase1 verify --phase1file <prev phase1 file path> --output <curr phase1 file path>` to check the contribution of yourself;

    vi) Upload the output file, and publish its download URL and challenge hash.

## Phase2

In this phase, we use the Phase1 setup to compute the Groth16 parameters for three different circuits used in DKG verification.

1. The first contributor downloads the final Phase1 file, and run `go run mpccmd.go phase1 seal --phase1file <filepath> --output <filepath>` to get the SRS file, then run `go run mpccmd.go phase2 init --srsfile <phase1 file path> --output <phase2 file path> --batch <batch size>` (three times for batch 1, 2, 7) to get three different Phase2 files;

2. Following contributors should then compute based on existed Phase2 files one by one;

    i) Download the latest Phase2 file as your source file;
    
    ii) (Optional) If you are not the first or second contributor, you can run `go run mpccmd.go phase2 verify --phase2file <prev phase2 file path> --output <curr phase2 file path>` to check whether the Phase2 file you download is computed based on the correct source file;

    iii) (Optional) If you don't trust and want to verify the whole chain of MPC computation, then you need to download all Phase1 files before you, and use `go run mpccmd.go phase2 verify` to check one by one;

    iv) Run `go run mpccmd.go phase2 contribute --phase2file <prev phase2 file path> --output <curr phase2 file path>` in the `/cmd` directory, to contribute to your source file, and get a new Phase2 file;

    v) (Optional) If you are not the first contributor, you can run `go run mpccmd.go phase2 verify --phase2file <prev phase2 file path> --output <curr phase2 file path>` to check the contribution of yourself;

    vi) Upload the output file, and publish its download URL and challenge hash.

3. After all contributors participant the MPC, anyone can use `go run mpccmd.go seal --batch <size> --srsfile <filepath> --phase2file <filepath> --contract <filepath> --provingkey <filepath> --verifyingkey <filepath> --r1cs <filepath>` to output the contract verifiers we will use for Neo X.

## File Upload/Download

We use NeoFS to store and share every Phase1 and Phase2 file generated in Groth16 ceremony. Here is the introduction of its usage.

1. Download the latest `neofs-cli` from https://github.com/nspcc-dev/neofs-node/releases/download/v0.47.1/neofs-cli-linux-amd64 (change the build depends on your platform);

2. Download the latest `neo-go` from https://github.com/nspcc-dev/neo-go/releases/download/v0.110.0/neo-go-linux-amd64 (change the build depends on your platform);

3. Init a local wallet through `neo-go wallet init -w wallet.json`. Import existed account by `neo-go wallet import --wallet wallet.json --wif <WIF>` or create a new account by `neo-go wallet create --wallet wallet.json`;

4. (Only container owner) Bridge GAS from N3 to NeoFS through https://panel.fs.neo.org/ (This is for Mainnet only);

5. Upload a file by `NEOFS_CLI_PASSWORD={password} neofs-cli --rpc-endpoint {insecure_endpoint} --wallet {wallet_path} object put --cid {cid} --file {file_path} --timeout {put_timeout}`

6. Download a file by `NEOFS_CLI_PASSWORD={password} neofs-cli --rpc-endpoint {insecure_endpoint} --wallet {wallet_path} object get --cid {cid} --oid {oid} --file {file_path} --timeout {get_timeout}`

The following is a list of parameters we recommend for Mainnet/Testnet.

|   Parameter    |          Mainnet          |       Testnet        |
|----------------|---------------------------|----------------------|
|`--rpc-endpoint`|st1.storage.fs.neo.org:8080|st1.t5.fs.neo.org:8080|
|  `--timeout`   |            24h            |         24h          |

The `DELETE` operation should be disabled during ceremony, and the container should turn to read-only after ceremony.

All uploaded files will be copy to NGD cloud storage, the NeoFS container ID, object IDs and cloud URLs should be posted in this repository for further reference.

## Recommended Hardware

A 16-core CPU with at least 32 GB RAM.

This machine is only required for MPC, and can be released immediately after ceremony.

Please run `zk-dkg` on an individual machine, since the ceremony is heavy in computation.