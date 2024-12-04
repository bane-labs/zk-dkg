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
Stage one: in the `phase1` class
1) Call `InitPhase1(path string, power int)` to set the size of powoftau;
2) The current participant calls `ContributePhase1(prevPath string, nextPath string)` in sequence to set the file path and generation path of the previous participant. The function will also verify the legality of the files of the participants in the previous round;
3) Other participants call `VerifyPhase1(prevPath string, curPath string)` to verify the legality of the file submitted by the current participant;
4) Cycle through steps two and three until all participants complete calculation and verification.
   
Second stage: in `phase2` class
1) Call `InitPhase2(ccs constraint.ConstraintSystem, phase1Path string, phase2Path string)` to set the circuit rules of phase 2, the phase 1 file path and the phase 2 file generation path;
2) The current participant calls `ContributePhase2(prevPath string, nextPath string)` in sequence to set the file path and generation path of the previous participant. The function will also verify the legality of the files of the participants in the previous round;
3) Other participants call `VerifyPhase2(prevPath string, curPath string)` to verify the legality of the file submitted by the current participant;
4) Cycle through steps two and three until all participants complete calculation and verification.