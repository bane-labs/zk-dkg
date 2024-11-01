package circom

import (
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	fr_secp "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"golang.org/x/crypto/sha3"
	"math/big"
)

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
