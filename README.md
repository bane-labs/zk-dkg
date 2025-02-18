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
Stage one:
1) `go run mpccmd.go phase1 init --output <phase1 file path>`,this command is used to generate the phase1 initial file
2) `go run mpccmd.go phase1 contribute --input <prev phase1 file path> --output <curr phase1 file path>`,this command is used by participants in this round to calculate phase1 data
3) `go run mpccmd.go phase1 verify --input <prev phase1 file path> --output <curr phase1 file path>`,this command is used by other participants to verify phase1 data

Repeat steps 2-3 in a loop until all participants complete the calculation and verification work of phase1.

Stage two:
1) `go run mpccmd.go phase2 init --input <phase1 file path> --output <phase2 file path> --batch <batch size>`,此this command is used to generate the phase2 initial file
2) `go run mpccmd.go phase2 contribute --input <prev phase2 file path> --output <curr phase2 file path>`,this command is used by participants in this round to calculate phase2 data
3) `go run mpccmd.go phase2 verify --input <prev phase2 file path> --output <curr phase2 file path>`,this command is used by other participants to verify phase2 data

Repeat steps 2-3 in a loop until all participants complete the calculation and verification work of phase2.

Export contract:
- `go run mpccmd.go contract export --phase1file <phase1 file path> --phase2file <phase2 file path> --batch <batch size> --contract <verify-contract file path>`,this command is used to export verification contracts after mpc has completed