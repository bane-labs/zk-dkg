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
func transformKeyShare(fi *fr_bls12381.Element) ([]byte, *big.Int, *bls12381.G1Affine) {
	fiInt := fi.BigInt(new(big.Int))
	fiBytes := make([]byte, 32)
	fiInt.FillBytes(fiBytes)
	_, _, g1, _ := bls12381.Generators()
	bigFi := new(bls12381.G1Affine).ScalarMultiplication(&g1, fiInt)
	return fiBytes, fiInt, bigFi
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
func encryptKeyShare(pub *ecies.PublicKey, fiBytes []byte) ([]byte, []byte, *big.Int, *secp256k1.G1Affine, error) {
	return encryption.ECIESEncrypt(pub, fiBytes)
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
func PrepareEncryptedKeyShares(pubs []*ecies.PublicKey, fis []*fr_bls12381.Element) ([][]byte, []*big.Int, []*bls12381.G1Affine, [][]byte, [][]byte, []*big.Int, []*secp256k1.G1Affine, error) {
	amount := len(pubs)
	fisBytes := make([][]byte, amount)
	fisInts := make([]*big.Int, amount)
	bigFis := make([]*bls12381.G1Affine, amount)
	nonces := make([][]byte, amount)
	encryptedFis := make([][]byte, amount)
	rs := make([]*big.Int, amount)
	bigRs := make([]*secp256k1.G1Affine, amount)
	var err error
	for i := 0; i < amount; i++ {
		fisBytes[i], fisInts[i], bigFis[i] = transformKeyShare(fis[i])
		nonces[i], encryptedFis[i], rs[i], bigRs[i], err = encryptKeyShare(pubs[i], fisBytes[i])
		if err != nil {
			return nil, nil, nil, nil, nil, nil, nil, err
		}
	}
	return fisBytes, fisInts, bigFis, nonces, encryptedFis, rs, bigRs, nil
}
