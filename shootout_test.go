// Copyright 2017 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

package aesctrhmac

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

type size struct {
	name string
	l    int
}

var sizes = []size{
	{"32", 32},
	{"128", 128},
	{"1K", 1 * 1024},
	{"16K", 16 * 1024},
	{"128K", 128 * 1024},
	{"1M", 1024 * 1024},
}

func benchmarkAEAD(b *testing.B, c cipher.AEAD, l int) {
	input := make([]byte, l)
	output := make([]byte, 0, l+c.Overhead())
	nonce := make([]byte, c.NonceSize())

	b.SetBytes(int64(l))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c.Seal(output, nonce, input, nil)
	}
}

func BenchmarkAES128CTRWithHMACSHA256(b *testing.B) {
	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			key := make([]byte, 16+32)
			c, _ := New(key)

			benchmarkAEAD(b, c, size.l)
		})
	}
}

func BenchmarkAES256CTRWithHMACSHA256(b *testing.B) {
	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			key := make([]byte, 32+32)
			c, _ := New(key)

			benchmarkAEAD(b, c, size.l)
		})
	}
}

func BenchmarkAES128GCM(b *testing.B) {
	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			key := make([]byte, 16)
			a, _ := aes.NewCipher(key)
			c, _ := cipher.NewGCM(a)

			benchmarkAEAD(b, c, size.l)
		})
	}
}

func BenchmarkAES256GCM(b *testing.B) {
	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			key := make([]byte, 32)
			a, _ := aes.NewCipher(key)
			c, _ := cipher.NewGCM(a)

			benchmarkAEAD(b, c, size.l)
		})
	}
}

func BenchmarkChaCha20Poly1305(b *testing.B) {
	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			key := make([]byte, chacha20poly1305.KeySize)
			c, _ := chacha20poly1305.New(key)

			benchmarkAEAD(b, c, size.l)
		})
	}
}
