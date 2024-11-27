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
 * Function:ECIESEncrypt
 * @Description: mix encryption method
 * @param pb: public key
 * @param ptt: plain text string
 * @return nonce: salt
 * @return ctt: cipher text string
 * @return rs: integer form of random number
 * @return rb: the point on the elliptic curve corresponding to the random number
 */
func ECIESEncrypt(pb ecies.PublicKey, ptt []byte) (nonce []byte, ctt []byte, rs big.Int, rb secp256k1.G1Affine) {
	// Format public key
	var px fp.Element
	px.SetBigInt(pb.X)
	var py fp.Element
	py.SetBigInt(pb.Y)
	Pub := secp256k1.G1Affine{
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
	rPub.ScalarMultiplication(&Pub, &rs)
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
	ctt, nonce = AESGcmEncrypt(key, ptt)
	return
}

/**
 * Function:ECIESDecrypt
 * @Description: decryption method
 * @param prv: private key
 * @param ctt: cipher text string
 * @param nonce: salt
 * @param rb: the point on the elliptic curve corresponding to the random number
 * @return ptt: plain text string
 * @return err: error
 */
func ECIESDecrypt(prv *ecies.PrivateKey, ctt []byte, nonce []byte, rb secp256k1.G1Affine) (ptt []byte, err error) {
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
	ptt = AESGcmDecrypt(key, ctt, nonce)
	return
}
