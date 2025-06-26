package encryption

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	fr_secp "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"golang.org/x/crypto/sha3"
)

/**
 * Function: ECIESEncrypt
 * @Description: mix encryption method
 * @param pub: public key
 * @param plaintext: plain text string
 * @return nonce: salt
 * @return ciphertext: cipher text string
 * @return r: integer form of random number
 * @return bigR: the point on the elliptic curve corresponding to the random number
 * @return err: error
 */
func ECIESEncrypt(pub *ecies.PublicKey, plaintext []byte) ([]byte, []byte, *big.Int, *secp256k1.G1Affine, error) {
	// Format public key
	pg1 := new(secp256k1.G1Affine)
	pg1.X.SetBigInt(pub.X)
	pg1.Y.SetBigInt(pub.Y)
	// Generate random r, bigR=rG
	_, g := secp256k1.Generators()
	rs, err := new(fr_secp.Element).SetRandom()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	r := rs.BigInt(new(big.Int))
	bigR := new(secp256k1.G1Affine).ScalarMultiplication(&g, r)
	// Compute rPub=r*PublicKey
	rPub := new(secp256k1.G1Affine).ScalarMultiplication(pg1, r)
	// Compute rPubBytes=hash(rPub)
	nbBytes := 2 * fr_secp.Bytes
	rPubBytes := make([]byte, nbBytes*8)
	for i := 0; i < nbBytes; i++ {
		for j := 0; j < 8; j++ {
			rPubBytes[i*8+j] = (rPub.RawBytes()[i] >> (7 - j)) & 1
		}
	}
	hashBuilder := sha3.New256()
	hashBuilder.Write(rPubBytes)
	key := hashBuilder.Sum(nil)
	ciphertext, nonce, err := AESGCMEncrypt(key, plaintext)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return nonce, ciphertext, r, bigR, nil
}

/**
 * Function: ECIESDecrypt
 * @Description: decryption method
 * @param prv: private key
 * @param ciphertext: cipher text string
 * @param nonce: salt
 * @param bigR: the point on the elliptic curve corresponding to the random number
 * @return plaintext: plain text string
 * @return err: error
 */
func ECIESDecrypt(prv *ecies.PrivateKey, ciphertext []byte, nonce []byte, bigR *secp256k1.G1Affine) ([]byte, error) {
	// Compute rPub=r*PublicKey
	rPub := new(secp256k1.G1Affine).ScalarMultiplication(bigR, prv.D)
	// Compute rPubBytes=hash(rPub)
	nbBytes := 2 * fr_secp.Bytes
	rPubBytes := make([]byte, nbBytes*8)
	for i := 0; i < nbBytes; i++ {
		for j := 0; j < 8; j++ {
			rPubBytes[i*8+j] = (rPub.RawBytes()[i] >> (7 - j)) & 1
		}
	}
	hashBuilder := sha3.New256()
	hashBuilder.Write(rPubBytes)
	key := hashBuilder.Sum(nil)
	return AESGCMDecrypt(key, ciphertext, nonce)
}
