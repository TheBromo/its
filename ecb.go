package main

import "crypto/cipher"

type ecbEncrypter struct{ cipher.Block }

func newECBEncrypter(b cipher.Block) cipher.BlockMode {
	return ecbEncrypter{b}
}

func (x ecbEncrypter) BlockSize() int {
	return x.Block.BlockSize()
}

func (x ecbEncrypter) CryptBlocks(dst, src []byte) {
	size := x.BlockSize()
	if len(src)%size != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.Encrypt(dst, src)
		src, dst = src[size:], dst[size:]
	}
}
