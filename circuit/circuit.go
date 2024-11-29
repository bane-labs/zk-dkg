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
 * Function:ComputingAssignment
 * @Description: get input data collection for a zk proof calculation of a key fragment generating process
 * @param pubKey: public key required for asymmetric encryption
 * @param rs: the integer format of random number
 * @param rb: the corresponding elliptic curve point of random number
 * @param fiBytes: the serialization format of the key
 * @param sfi: the integer format of the key
 * @param bfi: the corresponding elliptic curve point of the key
 * @param ctt: a encrypted key fragments
 * @param nonce: salt
 * @return css: circuit constraints
 * @return circuit: circuit
 * @return assignment: input data collection
 * @return err: error
 */
func ComputingAssignment(pubKey ecies.PublicKey, rs big.Int, rb secp256k1.G1Affine, fiBytes []byte, sfi big.Int, bfi bls12381.G1Affine, ctt []byte, nonce []byte) (css constraint.ConstraintSystem, circuit ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], assignment ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], err error) {
	// Format data
	plainChunksBytes := make([]frontend.Variable, len(fiBytes))
	for i := 0; i < len(fiBytes); i++ {
		plainChunksBytes[i] = fiBytes[i]
	}
	ciphertextBytes := make([]frontend.Variable, len(ctt))
	for i := 0; i < len(ctt); i++ {
		ciphertextBytes[i] = ctt[i]
	}
	nonceBytes := [12]frontend.Variable{}
	for i := 0; i < len(nonce); i++ {
		nonceBytes[i] = nonce[i]
	}
	var px fp.Element
	px.SetBigInt(pubKey.X)
	var py fp.Element
	py.SetBigInt(pubKey.Y)
	Pub := secp256k1.G1Affine{
		X: px,
		Y: py,
	}
	// Compute RPub
	var RPub secp256k1.G1Affine
	RPub.ScalarMultiplication(&Pub, &rs)
	// Compute allHash
	nbBytes := 2 * fr_secp.Bytes
	rawBigR := rb.RawBytes()
	RawBigR := make([]byte, 2*fr_secp.Bytes*8)
	for i := 0; i < nbBytes; i++ {
		for j := 0; j < 8; j++ {
			RawBigR[i*8+j] = (rawBigR[i] >> (7 - j)) & 1
		}
	}
	rawPub := Pub.RawBytes()
	RawPub := make([]byte, 2*fr_secp.Bytes*8)
	for i := 0; i < nbBytes; i++ {
		for j := 0; j < 8; j++ {
			RawPub[i*8+j] = (rawPub[i] >> (7 - j)) & 1
		}
	}
	rawFi := bfi.RawBytes()
	RawFi := make([]byte, 2*fr_secp.Bytes*8)
	for i := 0; i < nbBytes; i++ {
		for j := 0; j < 8; j++ {
			RawFi[i*8+j] = (rawFi[i] >> (7 - j)) & 1
		}
	}
	temp := append(append(append(append(append(RawBigR, RawPub...), RawFi...), nonce...), 2), ctt...)
	raw_allHash := helper.GetHash(temp)
	allHash := make([]frontend.Variable, len(raw_allHash))
	for i := 0; i < len(allHash); i++ {
		allHash[i] = raw_allHash[i]
	}

	// Compute proof
	circuit = ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		PlainChunks:  make([]frontend.Variable, len(plainChunksBytes)),
		CipherChunks: make([]frontend.Variable, len(ciphertextBytes)),
		PubInputHash: make([]frontend.Variable, len(allHash)),
	}
	css, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, circuit, assignment, err
	}

	assignment = ECIESWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		SmallR: emulated.ValueOf[emulated.Secp256k1Fr](rs),
		BigR: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](rb.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](rb.Y),
		},
		Pub: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](Pub.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](Pub.Y),
		},
		RPub: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](RPub.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](RPub.Y),
		},
		PlainChunks:  plainChunksBytes,
		Iv:           nonceBytes,
		ChunkIndex:   2,
		CipherChunks: ciphertextBytes,

		SmallFi: emulated.ValueOf[emulated.BLS12381Fr](sfi),
		Fi: sw_emulated.AffinePoint[emulated.BLS12381Fp]{
			X: emulated.ValueOf[emulated.BLS12381Fp](bfi.X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](bfi.Y),
		},
		PubInputHash: allHash,
	}
	return
}

/**
 * Function:BatchComputingAssignment
 * @Description: get input data collection for a zk proof calculation of key fragments batch generating process
 * @param batch: batch size
 * @param pubKey: a set of public keys required for asymmetric encryption
 * @param rs: a set of the integer format of random numbers
 * @param rb: a set of the corresponding elliptic curve point of random numbers
 * @param fiBytes: a set of the serialization format of the keys
 * @param sfi: a set of the integer format of the keys
 * @param bfi: a set of the corresponding elliptic curve points of the key
 * @param ctt: a set of encrypted key fragments
 * @param nonce: a set of salt
 * @return css: circuit constraints
 * @return circuit: circuit
 * @return assignment: input data collection
 * @return err: error
 */
func BatchComputingAssignment(batch int, pubKey []ecies.PublicKey, rs []big.Int, rb []secp256k1.G1Affine, fiBytes [][]byte, sfi []big.Int, bfi []bls12381.G1Affine, ctt [][]byte, nonce [][]byte) (css constraint.ConstraintSystem, circuit BatchEncryptionWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], assignment *BatchEncryptionWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], err error) {
	Accounts := make([]AccountConstraints[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], batch)
	rawPubInputs := make([]byte, 0)
	for index := 0; index < batch; index++ {
		// Format data
		plainChunksBytes := make([]frontend.Variable, len(fiBytes[index]))
		for i := 0; i < len(fiBytes[index]); i++ {
			plainChunksBytes[i] = fiBytes[index][i]
		}
		ciphertextBytes := make([]frontend.Variable, len(ctt[index]))
		for i := 0; i < len(ctt[index]); i++ {
			ciphertextBytes[i] = ctt[index][i]
		}
		nonceBytes := [12]frontend.Variable{}
		for i := 0; i < len(nonce[index]); i++ {
			nonceBytes[i] = nonce[index][i]
		}
		var px fp.Element
		px.SetBigInt(pubKey[index].X)
		var py fp.Element
		py.SetBigInt(pubKey[index].Y)
		Pub := secp256k1.G1Affine{
			X: px,
			Y: py,
		}
		// Compute RPub
		var RPub secp256k1.G1Affine
		RPub.ScalarMultiplication(&Pub, &rs[index])
		// Compute allHash
		nbBytes := 2 * fr_secp.Bytes
		rawBigR := rb[index].RawBytes()
		RawBigR := make([]byte, 2*fr_secp.Bytes*8)
		for i := 0; i < nbBytes; i++ {
			for j := 0; j < 8; j++ {
				RawBigR[i*8+j] = (rawBigR[i] >> (7 - j)) & 1
			}
		}
		rawPub := Pub.RawBytes()
		RawPub := make([]byte, 2*fr_secp.Bytes*8)
		for i := 0; i < nbBytes; i++ {
			for j := 0; j < 8; j++ {
				RawPub[i*8+j] = (rawPub[i] >> (7 - j)) & 1
			}
		}
		rawFi := bfi[index].RawBytes()
		RawFi := make([]byte, 2*fr_secp.Bytes*8)
		for i := 0; i < nbBytes; i++ {
			for j := 0; j < 8; j++ {
				RawFi[i*8+j] = (rawFi[i] >> (7 - j)) & 1
			}
		}
		var Account AccountConstraints[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]
		Account.SmallR = emulated.ValueOf[emulated.Secp256k1Fr](rs[index])
		Account.BigR = sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](rb[index].X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](rb[index].Y),
		}
		Account.Pub = sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](Pub.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](Pub.Y),
		}
		Account.RPub = sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](RPub.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](RPub.Y),
		}
		Account.PlainChunks = plainChunksBytes
		Account.Iv = nonceBytes
		Account.ChunkIndex = 2
		Account.CipherChunks = ciphertextBytes

		Account.SmallFi = emulated.ValueOf[emulated.BLS12381Fr](sfi[index])
		Account.BigFi = sw_emulated.AffinePoint[emulated.BLS12381Fp]{
			X: emulated.ValueOf[emulated.BLS12381Fp](bfi[index].X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](bfi[index].Y),
		}
		Accounts[index] = Account
		rawPubInputs = append(rawPubInputs, append(append(append(append(append(RawBigR, RawPub...), RawFi...), nonce[index]...), 2), ctt[index]...)...)
	}
	rawCommandHash := helper.GetHash(rawPubInputs)
	CommandHash := make([]frontend.Variable, len(rawCommandHash))
	for i := 0; i < len(rawCommandHash); i++ {
		CommandHash[i] = rawCommandHash[i]
	}
	assignment = &BatchEncryptionWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		Account:      Accounts,
		CommentsHash: CommandHash,
	}
	circuit = BatchEncryptionWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		Account:      make([]AccountConstraints[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr], batch),
		CommentsHash: make([]frontend.Variable, 32),
	}
	for i := 0; i < batch; i++ {
		circuit.Account[i].PlainChunks = make([]frontend.Variable, len(fiBytes[i]))
		circuit.Account[i].CipherChunks = make([]frontend.Variable, len(ctt[i]))
	}

	css, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, circuit, nil, err
	}
	return
}
