package ecb

import (
	"crypto/cipher"
	"fmt"
)

type ecb struct {
	b         cipher.Block
	blockSize int
	tmp       []byte
}

func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
		tmp:       make([]byte, b.BlockSize()),
	}
}

type ecbEncrypter ecb

// NewECBEncrypter returns a BlockMode which encrypts in elecronic codebook (ECB)
// mode, using the given Block (Cipher).
func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(newECB(b))
}

func (x *ecbEncrypter) BlockSize() int { return x.blockSize }

func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	var errorMessage string
	if len(src)%x.blockSize != 0 {
		errorMessage = fmt.Sprintf("crypto/cipher: input not full blocks, received source len '%v' blocksize '%v'",
			len(src), x.blockSize)
		panic(errorMessage)
	}
	if len(dst) < len(src) {
		errorMessage = fmt.Sprintf("crypto/cipher: output '%v' smaller than input '%v'", len(dst), len(src))
		panic(errorMessage)
	}
	for len(src) > 0 {
		x.b.Encrypt(dst[:x.blockSize], src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

type ecbDecrypter ecb

// NewECBDecrypter returns a BlockMode which decrypts in electronic codebook (ECB)
// mode, using the given Block.
func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(b))
}

func (x *ecbDecrypter) BlockSize() int { return x.blockSize }

func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	var errorMessage string
	if len(src)%x.blockSize != 0 {
		errorMessage = fmt.Sprintf("crypto/cipher: input not full blocks, received source len '%v' blocksize '%v'", len(src), x.blockSize)
		panic(errorMessage)
	}
	if len(dst) < len(src) {
		errorMessage = fmt.Sprintf("crypto/cipher: output '%v' smaller than input '%v'", len(dst), len(src))
		panic(errorMessage)
	}
	if len(src) == 0 {

		return
	}
	for len(src) > 0 {
		x.b.Decrypt(dst[:x.blockSize], src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}
