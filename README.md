# zk-dkg
A zero knowledge library for Neo X's Anti-MEV key generation in Geth node.

## Provided Methods
`zkdkg.circuit` provides:
- Transform key shares to different type formats and encrypt them: `PrepareEncryptedKeyShares`;
- Circuits `AES256`, `ECIES` and `BatchEncryption`;
- Compute witness for key share encryption: `ComputeSingleKeyShareEncryptionAssignment`;
- Compute witness for a batch of key share encryption: `ComputeMultipleKeyShareEncryptionAssignment`.

`zkdkg.ecies` provides:
- ECIES encryption: `ECIESEncrypt`;
- ECIES decryption: `ECIESDecrypt`.

`zkdkg.helper` provides:
- Proof generation: `ComputeProof`;
- Export Solidity contracts: `ExportContract`;
- Export contracts inputs: `GetOutputData`;
- MPC parameter reader: `GetKeysFromExistedPlonkSetUp`.

For easy of use, `zkdkg` provides:
- Compute a zk proof and witness for a batch of DKG key share encryption: `ProveMultipleKeyShareEncryption`.

## Examples
- Batch proof: `TestRecursionEncryptionCircuit`.

## MPC usage process
1) `go run mpccmd.go export innerCircuit --inner-css <filesprefix>`,this command is used to generate inner ccs files,and 3 files will be generated.
2) `go run mpccmd.go CommonSRS init --inner-css <filepath> --srs <filepath>`,this command is used to generate initial srs file.
3) `go run mpccmd.go CommonSRS checkInit --inner-css <filepath> --srs <filepath>`,this command is used to check the legality of initial srs file.
4) `go run mpccmd.go CommonSRS contribute --inner-css <filepath> --input <filepath> --output <filepath>`,this command is used by participants in this round to calculate srs data
5) `go run mpccmd.go CommonSRS verify --inner-css <filepath> --input <filepath> --output <filepath>`,this command is used by other participants to verify srs data
6) `go run mpccmd.go export innerSeal --srs <filepath> --inner-css <filesprefix> --inner-pk <outputpath> --inner-vk <outputpath>`,this command is used to generate inner pk and vk files.
7) `go run mpccmd.go export outerSeal --srs <filepath> --inner-css <filesprefix> --inner-pk <filesprefix> --inner-vk <filesprefix> --outer-css <outputpath> --outer-pk <outputpath> --outer-vk <outputpath> --contract <outputpath>`,this command is used to generate outer ccs ,pk and vk files

Repeat steps 2-5 in a loop until all participants complete the calculation and verification work of srs.
