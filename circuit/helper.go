package circuit

import (
	"math/big"

	"github.com/bane-labs/zk-dkg/encryption"
	"github.com/bane-labs/zk-dkg/helper"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

/**
 * Function: transformKeyShare
 * @Description: generate necessary data in different format for a single key share in zk dkg
 * @param fi: a key share in bls12381 fr
 * @return fiBytes: the key share in byte array
 * @return fiInt: the key share in integer
 * @return bigFi: the bls12381 commitment of the key share
 */
func transformKeyShare(fi fr_bls12381.Element) (fiBytes []byte, fiInt big.Int, bigFi bls12381.G1Affine) {
	fi.BigInt(&fiInt)
	fiBytes = make([]byte, 32)
	fiInt.FillBytes(fiBytes)
	_, _, g12381, _ := bls12381.Generators()
	bigFi.ScalarMultiplication(&g12381, &fiInt)
	return
}

/**
 * Function: encryptKeyShare
 * @Description: encrypt a key share
 * @param pub: a public key required for ecies encryption
 * @param fiBytes: a key share in byte array
 * @return nonce: the salt
 * @return encryptedFi: the encrypted key share
 * @return r: the random number generated and used ecies
 * @return bigR: the bls12381 commitment of the random number
 */
func encryptKeyShare(pub *ecies.PublicKey, fiBytes []byte) (nonce []byte, encryptedFi []byte, r big.Int, bigR secp256k1.G1Affine) {
	nonce, encryptedFi, r, bigR = encryption.ECIESEncrypt(pub, fiBytes)
	return
}

func computeSumHash(pub secp256k1.G1Affine, bigR secp256k1.G1Affine, bigFi bls12381.G1Affine, encryptedFi []byte, nonce []byte) []byte {
	secp256k1G1ByteLength := secp256k1.SizeOfG1AffineUncompressed
	bls12381G1ByteLength := bls12381.SizeOfG1AffineUncompressed
	bigRBytes := bigR.RawBytes()
	rawBigR := make([]byte, secp256k1G1ByteLength*8)
	for i := 0; i < secp256k1G1ByteLength; i++ {
		for j := 0; j < 8; j++ {
			rawBigR[i*8+j] = (bigRBytes[i] >> (7 - j)) & 1
		}
	}
	pubBytes := pub.RawBytes()
	rawPub := make([]byte, secp256k1G1ByteLength*8)
	for i := 0; i < secp256k1G1ByteLength; i++ {
		for j := 0; j < 8; j++ {
			rawPub[i*8+j] = (pubBytes[i] >> (7 - j)) & 1
		}
	}
	bigFiBytes := bigFi.RawBytes()
	rawBigFi := make([]byte, bls12381G1ByteLength*8)
	for i := 0; i < bls12381G1ByteLength; i++ {
		for j := 0; j < 8; j++ {
			rawBigFi[i*8+j] = (bigFiBytes[i] >> (7 - j)) & 1
		}
	}
	data := append(append(append(append(append(rawBigR, rawPub...), rawBigFi...), nonce...), 2), encryptedFi...)
	return helper.GetHash(data)
}
