# zk-dkg
A zero knowledge library for Neo X's Anti-MEV key generation in Geth node.

This library is only designed and implemented for Neo X's Anti-MEV, using this in any other use case may import potential security risks. E.g. the code doesn't compute a GCM tag for message authorization, because related check is ensure at smart contract level. So please evaluate carefully before referring to this library.

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
1) `go run mpccmd.go export innerCircuit --inner-ccs <filesprefix>`, this command is used to generate inner ccs files,and 3 files will be generated.
2) `go run mpccmd.go CommonSRS init --inner-ccs <filepath> --srs <filepath>`, this command is used to generate initial srs file.
3) `go run mpccmd.go CommonSRS checkInit --inner-ccs <filepath> --srs <filepath>`, this command is used to check the legality of initial srs file.
4) `go run mpccmd.go CommonSRS contribute --inner-ccs <filepath> --input <filepath> --output <filepath>`, this command is used by participants in this round to calculate srs data
5) `go run mpccmd.go CommonSRS verify --inner-ccs <filepath> --input <filepath> --output <filepath>`, this command is used by other participants to verify srs data
6) `go run mpccmd.go export innerSeal --srs <filepath> --beacon <string> --inner-ccs <filesprefix> --inner-pk <outputpath> --inner-vk <outputpath>`, this command is used to generate inner pk and vk files.
7) `go run mpccmd.go export outerSeal --srs <filepath> --beacon <string> --inner-ccs <filesprefix> --inner-pk <filesprefix> --inner-vk <filesprefix> --outer-ccs <outputpath> --outer-pk <outputpath> --outer-vk <outputpath> --contract <outputpath>`, this command is used to generate outer ccs ,pk and vk files

Repeat steps 2-5 in a loop until all participants complete the calculation and verification work of srs.

Note: The beacon challenge used in MPC sealing should only be evaluated after the final contribution, for its detail, please ref [gnark comment](https://github.com/Consensys/gnark/blob/v0.13.0/backend/groth16/bn254/mpcsetup/setup.go#L21-L24) and https://a16zcrypto.com/posts/article/public-randomness-and-randomness-beacons/. Some external-and-unpredictable variable before time `t` is preferred, e.g. the block hash of some Bitcoin/Ethereum after time `t`, so that the value can work as an entropy.