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
func encryptKeyShare(pub ecies.PublicKey, fiBytes []byte) (nonce []byte, encryptedFi []byte, r big.Int, bigR secp256k1.G1Affine) {
	nonce, encryptedFi, r, bigR = encryption.ECIESEncrypt(pub, fiBytes)
	return
}

/**
 * Function: PrepareEncryptedKeyShares
 * @Description: encrypt a batch of key shares and return related data
 * @param pubs: a set of public keys required for ecies encryption
 * @param fis: a set of key shares to be encrypted
 * @return fisBytes: a set of key shares, each in a byte array
 * @return fisInts: the key shares in integers
 * @return bigFis: the bls12381 commitments of the key shares
 * @return nonces: a set of salts
 * @return encryptedFis: a set of a encrypted key shares
 * @return rs: a set of the integer format of random number
 * @return bigRs: a set of the corresponding bls12381 commitment of random number
 */
func PrepareEncryptedKeyShares(pubs []ecies.PublicKey, fis []fr_bls12381.Element) (fisBytes [][]byte, fisInts []big.Int, bigFis []bls12381.G1Affine, nonces [][]byte, encryptedFis [][]byte, rs []big.Int, bigRs []secp256k1.G1Affine) {
	amount := len(pubs)
	fisBytes = make([][]byte, amount)
	fisInts = make([]big.Int, amount)
	bigFis = make([]bls12381.G1Affine, amount)
	nonces = make([][]byte, amount)
	encryptedFis = make([][]byte, amount)
	rs = make([]big.Int, amount)
	bigRs = make([]secp256k1.G1Affine, amount)
	for i := 0; i < amount; i++ {
		fisBytes[i], fisInts[i], bigFis[i] = transformKeyShare(fis[i])
		nonces[i], encryptedFis[i], rs[i], bigRs[i] = encryptKeyShare(pubs[i], fisBytes[i])
	}
	return
}
