package encryption

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
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
 * @return rs: integer form of random number
 * @return rb: the point on the elliptic curve corresponding to the random number
 */
func ECIESEncrypt(pub ecies.PublicKey, plaintext []byte) (nonce []byte, ciphertext []byte, rs big.Int, rb secp256k1.G1Affine) {
	// Format public key
	var px fp.Element
	px.SetBigInt(pub.X)
	var py fp.Element
	py.SetBigInt(pub.Y)
	pg1 := secp256k1.G1Affine{
		X: px,
		Y: py,
	}
	// Generate random r, rb=rG
	_, g := secp256k1.Generators()
	var r fr_secp.Element
	r.SetRandom()
	r.BigInt(&rs)
	rb.ScalarMultiplication(&g, &rs)
	// Compute rPub=r*PublicKey
	var rPub secp256k1.G1Affine
	rPub.ScalarMultiplication(&pg1, &rs)
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
	ciphertext, nonce = AESGCMEncrypt(key, plaintext)
	return
}

/**
 * Function: ECIESDecrypt
 * @Description: decryption method
 * @param prv: private key
 * @param ciphertext: cipher text string
 * @param nonce: salt
 * @param rb: the point on the elliptic curve corresponding to the random number
 * @return plaintext: plain text string
 * @return err: error
 */
func ECIESDecrypt(prv *ecies.PrivateKey, ciphertext []byte, nonce []byte, rb secp256k1.G1Affine) (plaintext []byte, err error) {
	// Compute rPub=r*PublicKey
	var rPub secp256k1.G1Affine
	rPub.ScalarMultiplication(&rb, prv.D)
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
	plaintext = AESGCMDecrypt(key, ciphertext, nonce)
	return
}
