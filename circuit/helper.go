package circuit

import (
	"math/big"

	"github.com/bane-labs/zk-dkg/encryption"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

/**
 * Function:GenerateFragementKey
 * @Description: generate a key fragment
 * @return fiBytes: the serialization format of the key
 * @return sfi: the integer format of the key
 * @return bfi: the corresponding elliptic curve point of the key
 */
func GenerateFragementKey(fi fr_bls12381.Element) (fiBytes []byte, sfi big.Int, bfi bls12381.G1Affine) {
	fi.BigInt(&sfi)
	fiBytes = make([]byte, 32)
	sfi.FillBytes(fiBytes)
	_, _, g12381, _ := bls12381.Generators()
	bfi.ScalarMultiplication(&g12381, &sfi)
	return
}

/**
 * Function:GenerateEncryptFragementKey
 * @Description: generate a encrypted key fragments
 * @param pb: public key required for asymmetric encryption
 * @return fiBytes: the serialization format of the key
 * @return sfi: the integer format of the key
 * @return bfi: the corresponding elliptic curve point of the key
 * @return nonce: salt
 * @return ctt: a encrypted key fragments
 * @return rs: the integer format of random number
 * @return rb: the corresponding elliptic curve point of random number
 */
func GenerateEncryptFragementKey(pb ecies.PublicKey, fi fr_bls12381.Element) (fiBytes []byte, sfi big.Int, bfi bls12381.G1Affine, nonce []byte, ctt []byte, rs big.Int, rb secp256k1.G1Affine) {
	fiBytes, sfi, bfi = GenerateFragementKey(fi)
	nonce, ctt, rs, rb = encryption.ECIESEncrypt(pb, fiBytes)
	return
}

/**
 * Function:BatchGenerateEncryptFragementKey
 * @Description: generate encryption key fragments in batch
 * @param pb: a set of public key required for asymmetric encryption
 * @return fiBytes: a set of the serialization format of the key
 * @return sfi: a set of the integer format of the key
 * @return bfi: a set of the corresponding elliptic curve point of the key
 * @return nonce: a set of salt
 * @return ctt: a set of a encrypted key fragments
 * @return rs: a set of the integer format of random number
 * @return rb: a set of the corresponding elliptic curve point of random number
 */
func BatchGenerateEncryptFragementKey(pb []ecies.PublicKey, fi []fr_bls12381.Element) (fiBytes [][]byte, sfi []big.Int, bfi []bls12381.G1Affine, nonce [][]byte, ctt [][]byte, rs []big.Int, rb []secp256k1.G1Affine) {
	fiBytes = make([][]byte, len(pb))
	sfi = make([]big.Int, len(pb))
	bfi = make([]bls12381.G1Affine, len(pb))
	nonce = make([][]byte, len(pb))
	ctt = make([][]byte, len(pb))
	rs = make([]big.Int, len(pb))
	rb = make([]secp256k1.G1Affine, len(pb))
	for i := 0; i < len(pb); i++ {
		fiBytes[i], sfi[i], bfi[i] = GenerateFragementKey(fi[i])
		nonce[i], ctt[i], rs[i], rb[i] = encryption.ECIESEncrypt(pb[i], fiBytes[i])
	}
	return
}
