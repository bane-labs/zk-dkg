# zk-dkg
A zero knowledge library for Neo X's Anti-MEV key generation in Geth node

## Provided Methods
`compution` class provide:
- Generate a fragement key:`GenerateFragementKey`
- Generate a encryption fragement key:`GenerateEncryptFragementKey`
- Batch generation encryption fragement keys:`BatchGenerateEncryptFragementKey`
- compute a zk proof and witness for encryption fragement key generation process:`GenerateProof` and `ComputingAssignment`
- compute a zk proof and witness for encryption fragement key batch generation process:`BatchGenerateProof` and `BatchComputingAssignment`

`mixencryption` class provide:
- Fragement Key encryption:`Encrypt(pb ecies.PublicKey, ptt []byte) `
- Fragement Key decryption:`Decrypt(prv *ecies.PrivateKey, ctt []byte, nonce []byte, rb secp256k1.G1Affine)`

## Use Case
- single proof:`Test_MixEncryption_Circuit` and `TestMixEncryptionByMPC`
- Batch proof:`Test_BatchEncryption_Circuit` and `TestBatchEncryptionByMPC`

## MPC usage process
Stage one: in the `mpcHelper` class
1) Call `InitPhase1(path string, power int)` to set the size of powoftau
2) The current participant calls `ContributePhase1(prevPath string, nextPath string)` in sequence to set the file path and generation path of the previous participant. The function will also verify the legality of the files of the participants in the previous round.
3) Other participants call `VerifyPhase1(prevPath string, curPath string)` to verify the legality of the file submitted by the current participant
4) Cycle through steps two and three until all participants complete calculation and verification
   Second stage: in `mpcHelper` class
1) Call `InitPhase2(ccs constraint.ConstraintSystem, phase1Path string, phase2Path string)` to set the circuit rules of phase 2, the phase 1 file path and the phase 2 file generation path
2) The current participant calls `ContributePhase2(prevPath string, nextPath string)` in sequence to set the file path and generation path of the previous participant. The function will also verify the legality of the files of the participants in the previous round.
3) Other participants call `VerifyPhase2(prevPath string, curPath string)` to verify the legality of the file submitted by the current participant
4) Cycle through steps two and three until all participants complete calculation and verification