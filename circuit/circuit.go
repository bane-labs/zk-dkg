package circuit

import (
	"math/big"

	"github.com/bane-labs/zk-dkg/helper"
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	fr_secp "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

/**
 * Function: ComputeSingleKeyShareEncryptionAssignment
 * @Description: get input data collection for a zk proof calculation of a key share generating process
 * @param pubKey: public key used for key share encryption
 * @param r: the integer format of random number
 * @param bigR: the corresponding elliptic curve point of random number
 * @param fiBytes: the key share in a byte array
 * @param fiInt: the integer format of the key share
 * @param bigFi: the bls12381 commitment of the key share
 * @param encryptedFi: the encrypted key
 * @param nonce: salt
 * @return css: circuit constraints
 * @return circuit: circuit
 * @return assignment: input data collection
 * @return err: error
 */
func ComputeSingleKeyShareEncryptionAssignment(pubKey ecies.PublicKey, r big.Int, bigR secp256k1.G1Affine, fiBytes []byte, fiInt big.Int, bigFi bls12381.G1Affine, encryptedFi []byte, nonce []byte) (css constraint.ConstraintSystem, circuit ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], assignment ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], err error) {
	// Format data
	plainChunksBytes := make([]frontend.Variable, len(fiBytes))
	for i := 0; i < len(fiBytes); i++ {
		plainChunksBytes[i] = fiBytes[i]
	}
	ciphertextBytes := make([]frontend.Variable, len(encryptedFi))
	for i := 0; i < len(encryptedFi); i++ {
		ciphertextBytes[i] = encryptedFi[i]
	}
	nonceBytes := [12]frontend.Variable{}
	for i := 0; i < len(nonce); i++ {
		nonceBytes[i] = nonce[i]
	}
	var px fp.Element
	px.SetBigInt(pubKey.X)
	var py fp.Element
	py.SetBigInt(pubKey.Y)
	pub := secp256k1.G1Affine{
		X: px,
		Y: py,
	}
	// Compute RPub
	var rPub secp256k1.G1Affine
	rPub.ScalarMultiplication(&pub, &r)
	// Compute allHash
	nbBytes := 2 * fr_secp.Bytes
	bigRBytes := bigR.RawBytes()
	rawBigR := make([]byte, 2*fr_secp.Bytes*8)
	for i := 0; i < nbBytes; i++ {
		for j := 0; j < 8; j++ {
			rawBigR[i*8+j] = (bigRBytes[i] >> (7 - j)) & 1
		}
	}
	pubBytes := pub.RawBytes()
	rawPub := make([]byte, 2*fr_secp.Bytes*8)
	for i := 0; i < nbBytes; i++ {
		for j := 0; j < 8; j++ {
			rawPub[i*8+j] = (pubBytes[i] >> (7 - j)) & 1
		}
	}
	bigFiBytes := bigFi.RawBytes()
	rawBigFi := make([]byte, 2*fr_secp.Bytes*8)
	for i := 0; i < nbBytes; i++ {
		for j := 0; j < 8; j++ {
			rawBigFi[i*8+j] = (bigFiBytes[i] >> (7 - j)) & 1
		}
	}
	temp := append(append(append(append(append(rawBigR, rawPub...), rawBigFi...), nonce...), 2), encryptedFi...)
	sumHash := helper.GetHash(temp)
	rawSumHash := make([]frontend.Variable, len(sumHash))
	for i := 0; i < len(rawSumHash); i++ {
		rawSumHash[i] = sumHash[i]
	}

	// Compute proof
	circuit = ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		PlainChunks:  make([]frontend.Variable, len(plainChunksBytes)),
		CipherChunks: make([]frontend.Variable, len(ciphertextBytes)),
		PubInputHash: make([]frontend.Variable, len(rawSumHash)),
	}
	css, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, circuit, assignment, err
	}

	assignment = ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		SmallR: emulated.ValueOf[emulated.Secp256k1Fr](r),
		BigR: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](bigR.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](bigR.Y),
		},
		Pub: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pub.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](pub.Y),
		},
		RPub: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](rPub.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](rPub.Y),
		},
		PlainChunks:  plainChunksBytes,
		Iv:           nonceBytes,
		ChunkIndex:   2,
		CipherChunks: ciphertextBytes,

		SmallFi: emulated.ValueOf[emulated.BLS12381Fr](fiInt),
		Fi: sw_emulated.AffinePoint[emulated.BLS12381Fp]{
			X: emulated.ValueOf[emulated.BLS12381Fp](bigFi.X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](bigFi.Y),
		},
		PubInputHash: rawSumHash,
	}
	return
}

/**
 * Function: ComputeMultipleKeyShareEncryptionAssignment
 * @Description: get input data collection for a zk proof calculation of key shares batch generating process
 * @param batch: batch size
 * @param pubKey: a set of public keys required for key share encryption
 * @param rs: a set of the integer format of random numbers
 * @param bigRs: a set of the corresponding elliptic curve point of random numbers
 * @param fisBytes: a set of the serialization format of the keys
 * @param fisInts: a set of the integer format of the keys
 * @param bigFis: a set of the corresponding elliptic curve points of the key
 * @param encryptedFis: a set of encrypted key shares
 * @param nonces: a set of salt
 * @return css: circuit constraints
 * @return circuit: circuit
 * @return assignment: input data collection
 * @return err: error
 */
func ComputeMultipleKeyShareEncryptionAssignment(batch int, pubKey []ecies.PublicKey, rs []big.Int, bigRs []secp256k1.G1Affine, fisBytes [][]byte, fisInts []big.Int, bigFis []bls12381.G1Affine, encryptedFis [][]byte, nonces [][]byte) (css constraint.ConstraintSystem, circuit BatchEncryptionWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], assignment *BatchEncryptionWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], err error) {
	accounts := make([]AccountConstraints[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], batch)
	rawPubInputs := make([]byte, 0)
	for index := 0; index < batch; index++ {
		// Format data
		plainChunksBytes := make([]frontend.Variable, len(fisBytes[index]))
		for i := 0; i < len(fisBytes[index]); i++ {
			plainChunksBytes[i] = fisBytes[index][i]
		}
		ciphertextBytes := make([]frontend.Variable, len(encryptedFis[index]))
		for i := 0; i < len(encryptedFis[index]); i++ {
			ciphertextBytes[i] = encryptedFis[index][i]
		}
		noncesBytes := [12]frontend.Variable{}
		for i := 0; i < len(nonces[index]); i++ {
			noncesBytes[i] = nonces[index][i]
		}
		var px fp.Element
		px.SetBigInt(pubKey[index].X)
		var py fp.Element
		py.SetBigInt(pubKey[index].Y)
		pub := secp256k1.G1Affine{
			X: px,
			Y: py,
		}
		// Compute RPub
		var rPub secp256k1.G1Affine
		rPub.ScalarMultiplication(&pub, &rs[index])
		// Compute allHash
		nbBytes := 2 * fr_secp.Bytes
		bigRsBytes := bigRs[index].RawBytes()
		rawBigRs := make([]byte, 2*fr_secp.Bytes*8)
		for i := 0; i < nbBytes; i++ {
			for j := 0; j < 8; j++ {
				rawBigRs[i*8+j] = (bigRsBytes[i] >> (7 - j)) & 1
			}
		}
		pubBytes := pub.RawBytes()
		rawPub := make([]byte, 2*fr_secp.Bytes*8)
		for i := 0; i < nbBytes; i++ {
			for j := 0; j < 8; j++ {
				rawPub[i*8+j] = (pubBytes[i] >> (7 - j)) & 1
			}
		}
		bigFisBytes := bigFis[index].RawBytes()
		rawBigFis := make([]byte, 2*fr_secp.Bytes*8)
		for i := 0; i < nbBytes; i++ {
			for j := 0; j < 8; j++ {
				rawBigFis[i*8+j] = (bigFisBytes[i] >> (7 - j)) & 1
			}
		}
		var account AccountConstraints[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]
		account.SmallR = emulated.ValueOf[emulated.Secp256k1Fr](rs[index])
		account.BigR = sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](bigRs[index].X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](bigRs[index].Y),
		}
		account.Pub = sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pub.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](pub.Y),
		}
		account.RPub = sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](rPub.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](rPub.Y),
		}
		account.PlainChunks = plainChunksBytes
		account.Iv = noncesBytes
		account.ChunkIndex = 2
		account.CipherChunks = ciphertextBytes

		account.SmallFi = emulated.ValueOf[emulated.BLS12381Fr](fisInts[index])
		account.BigFi = sw_emulated.AffinePoint[emulated.BLS12381Fp]{
			X: emulated.ValueOf[emulated.BLS12381Fp](bigFis[index].X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](bigFis[index].Y),
		}
		accounts[index] = account
		rawPubInputs = append(rawPubInputs, append(append(append(append(append(rawBigRs, rawPub...), rawBigFis...), nonces[index]...), 2), encryptedFis[index]...)...)
	}
	sumHash := helper.GetHash(rawPubInputs)
	rawSumHash := make([]frontend.Variable, len(sumHash))
	for i := 0; i < len(sumHash); i++ {
		rawSumHash[i] = sumHash[i]
	}
	assignment = &BatchEncryptionWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		Account:      accounts,
		CommentsHash: rawSumHash,
	}
	circuit = BatchEncryptionWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		Account:      make([]AccountConstraints[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], batch),
		CommentsHash: make([]frontend.Variable, 32),
	}
	for i := 0; i < batch; i++ {
		circuit.Account[i].PlainChunks = make([]frontend.Variable, len(fisBytes[i]))
		circuit.Account[i].CipherChunks = make([]frontend.Variable, len(encryptedFis[i]))
	}

	css, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, circuit, nil, err
	}
	return
}
