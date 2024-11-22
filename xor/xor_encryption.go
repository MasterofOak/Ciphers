package xor

import "crypto/rand"

/*
	Function which generates a key for XOR cypher

*/
func GenerateXORKey(size int) ([]byte, error) {
	key := make([]byte, size)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}
/*
	Function to encrypt and decrypt data using XOR cypher

*/
func XOREncrypt(data []byte, key []byte) []byte {
	cipher_text := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		cipher_text[i] = data[i] ^ key[i]
	}
	return cipher_text
}
