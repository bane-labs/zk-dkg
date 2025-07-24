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
 */
func transformKeyShare(fi *fr_bls12381.Element) ([]byte, *big.Int) {
	fiInt := fi.BigInt(new(big.Int))
	fiBytes := make([]byte, 32)
	fiInt.FillBytes(fiBytes)
	return fiBytes, fiInt
}

/**
 * Function: encryptKeyShare
 * @Description: encrypt a key share
 * @param pub: a public key required for ecies encryption
 * @param fiBytes: a key share in byte array
 * @return nonce: the salt
 * @return encryptedFi: the encrypted key share
 * @return r: the random number generated and used ecies
 * @return err: error
 */
func encryptKeyShare(pub *ecies.PublicKey, fiBytes []byte) ([]byte, []byte, *big.Int, error) {
	return encryption.ECIESEncrypt(pub, fiBytes)
}

/**
 * Function: computeSumHash
 * @Description: computes a sum hash for the public inputs of an ECIES circuit
 * @param pub: a public key required for ecies encryption
 * @param bigR: the corresponding elliptic curve point of random number
 * @param bigFi: the corresponding elliptic curve point of key share
 * @param encryptedFi: the encrypted key share
 * @param nonce: the salt
 * @return []byte: the hash of the public inputs
 */
func computeSumHash(pub *secp256k1.G1Affine, bigR *secp256k1.G1Affine, bigFi *bls12381.G1Affine, encryptedFi []byte, nonce []byte) []byte {
	secp256k1G1ByteLength := secp256k1.SizeOfG1AffineUncompressed
	bls12381G1ByteLength := bls12381.SizeOfG1AffineUncompressed
	bigRBytes := bigR.RawBytes()
	rawBigR := make([]byte, secp256k1G1ByteLength)
	for i := 0; i < secp256k1G1ByteLength; i++ {
		rawBigR[i] = bigRBytes[i] // bytes
	}
	pubBytes := pub.RawBytes()
	rawPub := make([]byte, secp256k1G1ByteLength)
	for i := 0; i < secp256k1G1ByteLength; i++ {
		rawPub[i] = pubBytes[i] // bytes
	}
	bigFiBytes := bigFi.RawBytes()
	rawBigFi := make([]byte, bls12381G1ByteLength)
	for i := 0; i < bls12381G1ByteLength; i++ {
		rawBigFi[i] = bigFiBytes[i] // bytes
	}
	data := append(append(append(append(append(rawBigR, rawPub...), rawBigFi...), nonce...), 2), encryptedFi...)
	return helper.GetHash(data)
}
