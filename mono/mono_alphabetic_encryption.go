package mono

import (
	"math/rand"
	"strings"
	"time"
)

var Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

/*
	Function which generates a key for mono-alphabetic cypher

*/
func GenerateMonoAlphabeticKey(length int) string {
	b := make([]byte, length)
	rand.New(rand.NewSource(time.Now().UnixNano()))
	perm := rand.Perm(length)
	for i, v := range perm {
		b[v] = Alphabet[i]
	}
	return string(b)
}
/*
	Function encrypt data using mono-alphabetic cypher

*/
func MonoAlphabeticEncrypt(data []byte, key string) []byte {
	cipher_text := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		letterIndex := strings.Index(Alphabet, strings.ToUpper(string(data[i])))
		if letterIndex < 0 {
			cipher_text[i] = data[i]
			continue
		}
		cipher_text[i] = key[letterIndex]
	}
	return cipher_text
}
/*
	Function decrypt data using mono-alphabetic cypher

*/
func MonoAlphabeticDecrypt(data []byte, key string) []byte {
	cipher_text := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		letterIndex := strings.Index(key, string(data[i]))
		if letterIndex < 0 {
			cipher_text[i] = data[i]
			continue
		}
		cipher_text[i] = Alphabet[letterIndex]
	}
	return cipher_text
}
