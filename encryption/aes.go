package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

/**
 * Function: AESGCMEncrypt
 * @Description: takes an encryption key and a plaintext string and encrypts it with AES256 in GCM mode
 * @param key: an encryption key
 * @param plaintext: plaintext string
 * @return ciphertext: ciphertext string
 * @return nonce: salt
 */
func AESGCMEncrypt(key []byte, plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

/**
 * Function: AESGCMDecrypt
 * @Description: takes an decryption key, a ciphertext and the corresponding nonce and decrypts it with AES256 in GCM mode.
 * @param key: an encryption key
 * @param ciphertext: ciphertext string
 * @param nonce: salt
 * @return plaintext: plaintext string
 */
func AESGCMDecrypt(key, ciphertext, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aesgcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce length: %d, expected %d", len(nonce), aesgcm.NonceSize())
	}
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
