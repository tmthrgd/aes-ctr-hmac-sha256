// Copyright 2017 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

// Package aesctrhmac is a AES-CTR + HMAC-SHA256 AEAD for Golang.
// It is compatibile with the |EVP_aead_aes_128_ctr_hmac_sha256|
// function in BoringSSL.
package aesctrhmac

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
)

var (
	// ErrAuthFailed is returned when the message authentication is invalid due
	// to tampering.
	ErrAuthFailed = errors.New("message authentication failed")

	// ErrInvalidKey is returned when the provided key is the wrong size.
	ErrInvalidKey = errors.New("invalid key size")

	// ErrInvalidNonce is panicked when the provided nonce is the wrong size.
	ErrInvalidNonce = errors.New("invalid nonce size")

	// ErrInvalidTagLength is returned when the provided tag length is invalid.
	ErrInvalidTagLength = errors.New("invalid tag length")

	// ErrTooLarge is panicjed if the internal counter would overflow.
	ErrTooLarge = errors.New("plaintext too large")
)

type aead struct {
	cipher cipher.Block
	hash   hash.Hash

	tagLen int
}

// New returns a new AES-CTR + HMAC-SHA256 AEAD
//
// The description of the algorithm, taken from BoringSSL, is:
//  |EVP_aead_aes_128_ctr_hmac_sha256| is AES-128 in CTR mode with HMAC-SHA256
//  for authentication. The nonce is 12 bytes; the bottom 32-bits are used as
//  the block counter, thus the maximum plaintext size is 64GB.
func New(key []byte) (cipher.AEAD, error) {
	return NewWithTagLength(key, sha256.Size)
}

// NewWithTagLength returns a new AES-CTR + HMAC-SHA256 AEAD
//
// The description of the algorithm, taken from BoringSSL, is:
//  |EVP_aead_aes_128_ctr_hmac_sha256| is AES-128 in CTR mode with HMAC-SHA256
//  for authentication. The nonce is 12 bytes; the bottom 32-bits are used as
//  the block counter, thus the maximum plaintext size is 64GB.
func NewWithTagLength(key []byte, tagLen int) (cipher.AEAD, error) {
	switch len(key) {
	case 16 + 32, 24 + 32, 32 + 32:
	default:
		return nil, ErrInvalidKey
	}

	if tagLen < 0 || tagLen > sha256.Size {
		return nil, ErrInvalidTagLength
	}

	cipher, err := aes.NewCipher(key[:len(key)-32])
	if err != nil {
		return nil, err
	}

	hash := hmac.New(sha256.New, key[len(key)-32:])
	return &aead{cipher, hash, tagLen}, nil
}

func (a *aead) NonceSize() int {
	return aes.BlockSize - 4
}

func (a *aead) Overhead() int {
	return a.tagLen
}

func (a *aead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != a.NonceSize() {
		panic(ErrInvalidNonce)
	}

	if uint64(len(plaintext)) >= (uint64(1)<<32)*aes.BlockSize {
		panic(ErrTooLarge)
	}

	ret, out := sliceForAppend(dst, len(plaintext)+a.tagLen)

	var iv [aes.BlockSize]byte
	copy(iv[:], nonce)

	c := cipher.NewCTR(a.cipher, iv[:])
	c.XORKeyStream(out, plaintext)

	tag := a.calculateTag(nonce, out[:len(plaintext)], additionalData)
	copy(out[len(plaintext):], tag)

	return ret
}

func (a *aead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != a.NonceSize() {
		panic(ErrInvalidNonce)
	}

	if len(ciphertext) < a.tagLen {
		return nil, ErrAuthFailed
	}

	tag := ciphertext[len(ciphertext)-a.tagLen:]
	ciphertext = ciphertext[:len(ciphertext)-a.tagLen]

	ret, out := sliceForAppend(dst, len(ciphertext))

	expectedTag := a.calculateTag(nonce, ciphertext[:len(ciphertext)], additionalData)
	if !hmac.Equal(expectedTag, tag) {
		// The AESNI code decrypts and authenticates concurrently, and
		// so overwrites dst in the event of a tag mismatch. That
		// behaviour is mimicked here in order to be consistent across
		// platforms.
		for i := range out {
			out[i] = 0
		}

		return nil, ErrAuthFailed
	}

	var iv [aes.BlockSize]byte
	copy(iv[:], nonce)

	c := cipher.NewCTR(a.cipher, iv[:])
	c.XORKeyStream(out, ciphertext)

	return ret, nil
}

var padding [sha256.BlockSize]byte

func (a *aead) calculateTag(nonce, ciphertext, additionalData []byte) []byte {
	binary.Write(a.hash, binary.LittleEndian, uint64(len(additionalData)))
	binary.Write(a.hash, binary.LittleEndian, uint64(len(ciphertext)))

	a.hash.Write(nonce)
	a.hash.Write(additionalData)

	a.hash.Write(padding[:(sha256.BlockSize-
		((8*2+len(nonce)+len(additionalData))%sha256.BlockSize))%
		sha256.BlockSize])

	a.hash.Write(ciphertext)

	tag := a.hash.Sum(nil)[:a.tagLen]
	a.hash.Reset()
	return tag
}

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}

	tail = head[len(in):]
	return
}
