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
 * @return r: integer form of random number
 * @return err: error
 */
func ECIESEncrypt(pub *ecies.PublicKey, plaintext []byte) ([]byte, []byte, *big.Int, error) {
	// Format public key
	var px fp.Element
	px.SetBigInt(pub.X)
	var py fp.Element
	py.SetBigInt(pub.Y)
	pg1 := secp256k1.G1Affine{
		X: px,
		Y: py,
	}
	// Generate random r, bigR=rG
	_, g := secp256k1.Generators()
	rs, err := new(fr_secp.Element).SetRandom()
	if err != nil {
		return nil, nil, nil, err
	}
	r := rs.BigInt(new(big.Int))
	bigR := new(secp256k1.G1Affine).ScalarMultiplication(&g, r)
	// Compute rPub=r*PublicKey
	rPub := new(secp256k1.G1Affine).ScalarMultiplication(&pg1, r)
	// Compute rPubBytes=hash(rPub.X, bigR)
	sxBytes := rPub.X.Bytes()
	// Serialize ephemeral public key
	bigRBytes := bigR.RawBytes()
	hashBuilder := sha3.New256()
	hashBuilder.Write(sxBytes[:])
	hashBuilder.Write(bigRBytes[:])
	key := hashBuilder.Sum(nil)
	ciphertext, nonce, err := AESGCMEncrypt(key, plaintext)
	if err != nil {
		return nil, nil, nil, err
	}
	return nonce, ciphertext, r, nil
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
	// Compute rPubBytes=hash(rPub.X, bigR)
	sxBytes := rPub.X.Bytes()
	// Serialize ephemeral public key
	bigRBytes := bigR.RawBytes()
	hashBuilder := sha3.New256()
	hashBuilder.Write(sxBytes[:])
	hashBuilder.Write(bigRBytes[:])
	key := hashBuilder.Sum(nil)
	return AESGCMDecrypt(key, ciphertext, nonce)
}
