package main

import (
	"cryptography/mono"
	"cryptography/xor"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)
/*
	Variables which stores values from cmd
*/
var filePath string
var pathToXORKey string
var pathToMonoKey string
var toEncrypt bool
var toDecrypt bool
var isXor bool
var isMono bool
var isBoth bool

//Simple function to output an error and understandable sentence
func showError(err error, msg string) {
	fmt.Println(msg)
	panic(err)
}
/*
	Self-explanatory

*/
func initFlags() {
	flag.StringVar(&filePath, "file", "", "Path to a file")
	flag.StringVar(&pathToXORKey, "kx", "", "Path to a xor key file")
	flag.StringVar(&pathToMonoKey, "km", "", "Path to a mono key file")
	flag.BoolVar(&toEncrypt, "e", false, "Add this flag if you want to encrypt file")
	flag.BoolVar(&toDecrypt, "d", false, "Add this flag if you want to decrypt file")
	flag.BoolVar(&isXor, "xor", false, "XOR encryption")
	flag.BoolVar(&isMono, "mono", false, "Mono-alphabetic encryption")
	flag.BoolVar(&isBoth, "a", false, "Use both encryption to encrypt or decrypt")
	flag.Parse()
}
/*
	Function to write a data to a file

*/
func writeDataToFile(data []byte, currentFilename string, fileExtension string) {
	filename := fmt.Sprintf("%s-%d%s", currentFilename, time.Now().UnixNano(), fileExtension)
	err := os.WriteFile(filename, data, 0666)
	if err != nil {
		showError(err, "Failed writing to a file")
	}
}
/*
	Function to write a generated key to a file

*/
func writeKeyToFile(key []byte, encryptionMethod string) {
	filename := fmt.Sprintf("key_%s.txt", encryptionMethod)
	err := os.WriteFile(filename, key, 0660)
	if err != nil {
		showError(err, "Failed writing to a file")
	}
}
/*
	Function to read a key if it is exist

*/
func readKeyFromFile(pathToKey string) []byte {
	keyData, err := os.ReadFile(pathToKey)
	if err != nil {
		showError(err, "Failed to read a key file")
	}
	return keyData
}
func main() {
	initFlags()
	fileExt := filepath.Ext(filePath) //Get extension of a file
	fileName := strings.TrimSuffix(filepath.Base(filePath), fileExt) //Get file name without extension
	fileData, err := os.ReadFile(filePath) // File data
	if err != nil {
		showError(err, "Failed to read a file")
	}
	if toEncrypt {
		switch {
		case isBoth || (isXor && isMono):
			keyXOR, err := xor.GenerateXORKey(len(fileData))
			if err != nil {
				showError(err, "Failed to generate a key")
			}
			keyMono := mono.GenerateMonoAlphabeticKey(len(mono.Alphabet))
			encrypted_mono_data := mono.MonoAlphabeticEncrypt(fileData, keyMono)
			encrypted_xor_data := xor.XOREncrypt(encrypted_mono_data, keyXOR)
			writeDataToFile(encrypted_xor_data, fileName, fileExt)
			writeKeyToFile(keyXOR, "xor")
			writeKeyToFile([]byte(keyMono), "mono_alphabetic")
		case isXor:
			keyXOR, err := xor.GenerateXORKey(len(fileData))
			if err != nil {
				showError(err, "Failed to generate a key")
			}
			encrypted_xor_data := xor.XOREncrypt(fileData, keyXOR)
			writeDataToFile(encrypted_xor_data, fileName, fileExt)
			writeKeyToFile(keyXOR, "xor")
		case isMono:
			keyMono := mono.GenerateMonoAlphabeticKey(len(mono.Alphabet))
			encrypted_mono_data := mono.MonoAlphabeticEncrypt(fileData, keyMono)
			writeDataToFile(encrypted_mono_data, fileName, fileExt)
			writeKeyToFile([]byte(keyMono), "mono_alphabetic")
		}
		return
	}
	if toDecrypt {
		switch {
		case isBoth || (isXor && isMono):
			keyXOR := readKeyFromFile(pathToXORKey)
			keyMono := readKeyFromFile(pathToMonoKey)
			decrypted_xor_data := xor.XOREncrypt(fileData, keyXOR)
			decrypted_mono_data := mono.MonoAlphabeticDecrypt(decrypted_xor_data, string(keyMono))
			writeDataToFile(decrypted_mono_data, fileName, fileExt)
		case isXor:
			keyXOR := readKeyFromFile(pathToXORKey)
			decrypted_xor_data := xor.XOREncrypt(fileData, keyXOR)
			writeDataToFile(decrypted_xor_data, fileName, fileExt)
		case isMono:
			keyMono := readKeyFromFile(pathToMonoKey)
			decrypted_mono_data := mono.MonoAlphabeticDecrypt(fileData, string(keyMono))
			writeDataToFile(decrypted_mono_data, fileName, fileExt)
		}
		return
	}

}
