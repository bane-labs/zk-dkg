// Provides mix encryption and decryption methods
package circom

import (
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	fr_secp "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"golang.org/x/crypto/sha3"
	"math/big"
)

/**
 * Function:Encrypt
 * @Description: mix encryption method
 * @param pb: public key
 * @param ptt: plain text string
 * @return nonce: salt
 * @return ctt: cipher text string
 * @return rs: integer form of random number
 * @return rb: the point on the elliptic curve corresponding to the random number
 */
func Encrypt(pb ecies.PublicKey, ptt []byte) (nonce []byte, ctt []byte, rs big.Int, rb secp256k1.G1Affine) {
	//format pubKey
	var px fp.Element
	px.SetBigInt(pb.X)
	var py fp.Element
	py.SetBigInt(pb.Y)
	Pub := secp256k1.G1Affine{
		px,
		py,
	}
	//generate random r,rb=rG
	_, g := secp256k1.Generators()
	var r fr_secp.Element
	r.SetRandom()
	r.BigInt(&rs)
	rb.ScalarMultiplication(&g, &rs)
	//generator rPub=r*PublicKey
	var rPub secp256k1.G1Affine
	rPub.ScalarMultiplication(&Pub, &rs)
	//generate rPubBytes=hash(rPub)
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
	ctt, nonce = AesGcmEncrypt(key, ptt)
	return
}

/**
 * Function:Decrypt
 * @Description: decryption method
 * @param prv: private key
 * @param ctt: cipher text string
 * @param nonce: salt
 * @param rb: the point on the elliptic curve corresponding to the random number
 * @return ptt: plain text string
 * @return err: error
 */
func Decrypt(prv *ecies.PrivateKey, ctt []byte, nonce []byte, rb secp256k1.G1Affine) (ptt []byte, err error) {
	//generator rPub=r*PublicKey
	var rPub secp256k1.G1Affine
	rPub.ScalarMultiplication(&rb, prv.D)
	//generator rPubBytes=hash(rPub)
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
	ptt = AesGcmDecrypt(key, ctt, nonce)
	return
}
