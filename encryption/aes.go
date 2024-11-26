package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// AESGcmEncrypt
//
//	@Description: takes an encryption key and a plaintext string and encrypts it with AES256 in GCM mode
//	@param key: an encryption key
//	@param plaintext: plaintext string
//	@return ciphertext: ciphertext string
//	@return nonce: salt
func AESGcmEncrypt(key []byte, plaintext []byte) (ciphertext, nonce []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce = make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext = aesgcm.Seal(nil, nonce, plaintext, nil)
	return
}

// AESGcmDecrypt
//
//	@Description: takes an decryption key, a ciphertext and the corresponding nonce and decrypts it with AES256 in GCM mode.
//	@param key: an encryption key
//	@param ciphertext: ciphertext string
//	@param nonce: salt
//	@return plaintext:
func AESGcmDecrypt(key, ciphertext, nonce []byte) (plaintext []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	plaintext, err = aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return
}
