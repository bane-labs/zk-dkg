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
- MPC parameter reader: `GetInitParamsFromExistedMPCSetUp`.

For easy of use, `zkdkg` provides:
- Compute a zk proof and witness for single DKG key share encryption: `ProveSingleKeyShareEncryption`;
- Compute a zk proof and witness for a batch of DKG key share encryption: `ProveMultipleKeyShareEncryption`.

## Examples
- Single proof: `TestECIESCircuit` and `TestECIESWithMPC`;
- Batch proof: `TestBatchEncryptionCircuit` and `TestBatchEncryptionWithMPC`.

## MPC usage process
Stage 1:
1) `go run mpccmd.go phase1 init --output <phase1 file path>`, this command is used to generate the phase1 initial file;
2) `go run mpccmd.go phase1 contribute --phase1file <prev phase1 file path> --output <curr phase1 file path>`, this command is used by participants in this round to calculate phase1 data;
3) `go run mpccmd.go phase1 verify --phase1file <prev phase1 file path> --output <curr phase1 file path>`, this command is used by other participants to verify phase1 data.

Repeat steps 2-3 in a loop until all participants complete the calculation and verification work of phase1.

Stage 1.5:
- `go run mpccmd.go phase1 seal --phase1file <filepath> --beacon <string> --output <filepath>`, this command is used to output SRS parameters for Stage 2 initialization.

Stage 2:
1) `go run mpccmd.go phase2 init --srsfile <filepath> --output <phase2 file path> --batch <batch size>`, this command is used to generate the phase2 initial file;
2) `go run mpccmd.go phase2 contribute --phase2file <prev phase2 file path> --output <curr phase2 file path>`, this command is used by participants in this round to calculate phase2 data;
3) `go run mpccmd.go phase2 verify --phase2file <prev phase2 file path> --output <curr phase2 file path>`, this command is used by other participants to verify phase2 data.

Repeat steps 2-3 in a loop until all participants complete the calculation and verification work of phase2.

Export contract:
- `go run mpccmd.go seal --batch <size> --srsfile <filepath> --phase2file <filepath> --beacon <string> --contract <filepath> --provingkey <filepath> --verifyingkey <filepath> --r1cs <filepath>`, this command is used to export verification contracts after mpc has completed.

Note: The beacon challenge used in MPC sealing should only be evaluated after the final contribution, for its detail, please ref [gnark comment](https://github.com/Consensys/gnark/blob/v0.13.0/backend/groth16/bn254/mpcsetup/setup.go#L21-L24) and https://a16zcrypto.com/posts/article/public-randomness-and-randomness-beacons/. Some external-and-unpredictable variable before time `t` is preferred, e.g. the block hash of some Bitcoin/Ethereum after time `t`, so that the value can work as an entropy.