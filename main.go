package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"image"
	"image/gif"
	"image/png"
	"io"
	"os"
)

func loadGif(path string) []byte {
	reader, err := os.Open(path)

	img, err := gif.Decode(reader)
	if err != nil {
		panic(err)
	}

	buf := new(bytes.Buffer)
	err = gif.Encode(buf, img, &gif.Options{})
	if err != nil {
		panic(err)
	}

	return buf.Bytes()
}

func loadPng(path string) []byte {
	reader, err := os.Open(path)

	img, _, err := image.Decode(reader)
	if err != nil {
		panic(err)
	}

	buf := new(bytes.Buffer)
	err = png.Encode(buf, img)
	if err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func main() {
	secret := "my secret is the"

	pngfile, err := os.ReadFile("tux.png")

	if err != nil {
		println(err.Error())
		return
	}

	giffile, err := os.ReadFile("tux.gif")

	if err != nil {
		println(err.Error())
		return
	}
	cfb(secret, pngfile, giffile)
	cbc(secret, pngfile, giffile)
	gcm(secret, pngfile, giffile)
	ecb(secret, pngfile, giffile)
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func ecb(secret string, pngfile, giffile []byte) {

	pngenc := EncryptECB(secret, pngfile)
	gifenc := EncryptECB(secret, giffile)

	os.WriteFile("tuxenc_ecb.png", pngenc, 0666)
	os.WriteFile("tuxenc_ecb.gif", gifenc, 0666)
}

func gcm(secret string, pngfile, giffile []byte) {

	pngenc := EncryptGCM(secret, pngfile)
	gifenc := EncryptGCM(secret, giffile)

	os.WriteFile("tuxenc_gcm.png", pngenc, 0666)
	os.WriteFile("tuxenc_gcm.gif", gifenc, 0666)
}

func cbc(secret string, pngfile, giffile []byte) {

	pngenc := EncryptCBC(secret, pngfile)
	gifenc := EncryptCBC(secret, giffile)

	os.WriteFile("tuxenc_cbc.png", pngenc, 0666)
	os.WriteFile("tuxenc_cbc.gif", gifenc, 0666)
}

func cfb(secret string, pngfile, giffile []byte) {
	pngenc, err := EncryptCFB(secret, pngfile, cipher.NewCFBEncrypter)
	gifenc, err := EncryptCFB(secret, giffile, cipher.NewCFBEncrypter)

	if err != nil {
		println(err.Error())
		return
	}

	os.WriteFile("tuxenc_cfb.png", pngenc, 0666)
	os.WriteFile("tuxenc_cfb.gif", gifenc, 0666)

}

func EncryptECB(secret string, file []byte) []byte {
	block, err := aes.NewCipher([]byte(secret))
	if err != nil {
		panic(err)
	}

	file = PKCS5Padding(file, block.BlockSize())

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(file))

	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := newECBEncrypter(block)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], file)

	return ciphertext
}

func EncryptGCM(secret string, file []byte) []byte {
	block, err := aes.NewCipher([]byte(secret))
	if err != nil {
		panic(err)
	}

	file = PKCS5Padding(file, block.BlockSize())

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, file, nil)
	return ciphertext
}

func EncryptCBC(secret string, file []byte) []byte {
	block, err := aes.NewCipher([]byte(secret))
	if err != nil {
		panic(err)
	}

	file = PKCS5Padding(file, block.BlockSize())

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(file))

	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], file)

	return ciphertext
}

func EncryptCFB(secret string, value []byte, encryptor func(cipher.Block, []byte) cipher.Stream) ([]byte, error) {
	block, err := aes.NewCipher([]byte(secret))
	if err != nil {
		return nil, err
	}

	plainText := []byte(value)

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plainText))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := encryptor(block, iv)
	//stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plainText)

	return ciphertext, nil
}
