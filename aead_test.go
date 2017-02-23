// Copyright 2017 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

package aesctrhmac

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/quick"
)

type testCase struct {
	key, nonce, in, ad, ct, tag []byte
}

func readTestCases(path string) (cases []testCase) {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}

	var tc testCase

	s := bufio.NewScanner(f)

	for s.Scan() {
		if len(s.Bytes()) == 0 {
			cases = append(cases, tc)
			tc = testCase{}
			continue
		}

		p := strings.Split(s.Text(), ": ")

		b, err := hex.DecodeString(p[1])
		if err != nil {
			panic(err)
		}

		switch strings.ToUpper(p[0]) {
		case "KEY":
			tc.key = b
		case "NONCE":
			tc.nonce = b
		case "IN":
			tc.in = b
		case "AD":
			tc.ad = b
		case "CT":
			tc.ct = b
		case "TAG":
			tc.tag = b
		default:
			panic("unkown key")
		}
	}

	if s.Err() != nil {
		panic(s.Err())
	}

	return
}

var testCases []testCase

func init() {
	testCases = readTestCases("aes_128_ctr_hmac_sha256.txt")
	testCases = append(testCases, readTestCases("aes_256_ctr_hmac_sha256.txt")...)
}

func TestSeal(t *testing.T) {
	for i, test := range testCases {
		t.Run(fmt.Sprintf("%d", 1+i), func(t *testing.T) {
			a, err := New(test.key)
			if err != nil {
				t.Fatal(err)
			}

			out := a.Seal(nil, test.nonce, test.in, test.ad)
			if !bytes.Equal(out[:len(out)-len(test.tag)], test.ct) {
				t.Error("Seal failed")
				t.Logf("expected: %x", test.ct)
				t.Logf("got:      %x", out[:len(out)-len(test.tag)])
			} else if !bytes.Equal(out[len(out)-len(test.tag):], test.tag) {
				t.Error("Seal failed")
				t.Logf("expected: %x", test.tag)
				t.Logf("got:      %x", out[len(out)-len(test.tag):])
			}
		})
	}
}

func TestOpen(t *testing.T) {
	for i, test := range testCases {
		t.Run(fmt.Sprintf("%d", 1+i), func(t *testing.T) {
			a, err := New(test.key)
			if err != nil {
				t.Fatal(err)
			}

			ct := make([]byte, len(test.ct)+len(test.tag))
			copy(ct, test.ct)
			copy(ct[len(test.ct):], test.tag)

			out, err := a.Open(nil, test.nonce, ct, test.ad)
			if err != nil {
				t.Error("Open failed")
				t.Log(err)
			} else if !bytes.Equal(out, test.in) {
				t.Error("Open failed")
				t.Logf("expected: %x", test.in)
				t.Logf("got:      %x", out)
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	byteType := reflect.TypeOf([]byte(nil))

	if err := quick.CheckEqual(func(key, nonce, in, ad []byte, tagLen int) (out []byte, err error) {
		return in, nil
	}, func(key, nonce, in, ad []byte, tagLen int) (out []byte, err error) {
		c, err := NewWithTagLength(key, tagLen)
		if err != nil {
			return nil, err
		}

		ct := c.Seal([]byte{}, nonce, in, ad)
		return c.Open(ct[:0], nonce, ct, ad)
	}, &quick.Config{
		Values: func(values []reflect.Value, rand *rand.Rand) {
			key := make([]byte, 16+8*rand.Intn(3)+32)
			rand.Read(key)

			nonce := make([]byte, 12)
			rand.Read(nonce)

			in, ok0 := quick.Value(byteType, rand)

			ad, ok1 := quick.Value(byteType, rand)

			if !ok0 || !ok1 {
				panic("quick.Value failed")
			}

			tagLen := rand.Intn(32 + 1)

			values[0] = reflect.ValueOf(key)
			values[1] = reflect.ValueOf(nonce)
			values[2] = in
			values[3] = ad
			values[4] = reflect.ValueOf(tagLen)
		},

		MaxCountScale: 400,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidKey(t *testing.T) {
	key := make([]byte, 16+32-1)

	_, err := New(key)
	if err != ErrInvalidKey {
		t.Fatalf("Expected invalid key error but was %v", err)
	}
}

func TestSealInvalidNonce(t *testing.T) {
	key := make([]byte, 16+32)

	c, err := New(key)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, c.NonceSize()-3)
	plaintext := []byte("yay for me")
	data := []byte("whoah yeah")

	defer func() {
		if r := recover(); r != ErrInvalidNonce {
			t.Fatalf("Expected invalid key panic but was %v", r)
		}
	}()

	c.Seal(nil, nonce, plaintext, data)
}

func TestOpenInvalidNonce(t *testing.T) {
	key := make([]byte, 16+32)
	c, err := New(key)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, c.NonceSize())
	plaintext := []byte("yay for me")
	data := []byte("whoah yeah")
	ciphertext := c.Seal(nil, nonce, plaintext, data)

	defer func() {
		if r := recover(); r != ErrInvalidNonce {
			t.Fatalf("Expected invalid key panic but was %v", r)
		}
	}()

	c.Open(nil, nonce[:4], ciphertext, data)
}

func TestOpenTooShort(t *testing.T) {
	key := make([]byte, 16+32)
	c, err := New(key)

	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, c.NonceSize())
	plaintext := []byte("yay for me")
	data := []byte("whoah yeah")
	ciphertext := c.Seal(nil, nonce, plaintext, data)

	_, err = c.Open(nil, nonce, ciphertext[:2], data)
	if err != ErrAuthFailed {
		t.Fatalf("Expected message authentication failed error but was %v", err)
	}
}

func TestTagFailureOverwrite(t *testing.T) {
	// The AESNI GCM code decrypts and authenticates concurrently and so
	// overwrites the output buffer before checking the authentication tag.
	// In order to be consistent across platforms, all implementations
	// should do this and this test checks that.

	var vector testCase
	for _, test := range testCases {
		if len(test.ct) != 0 {
			vector = test
			break
		}
	}

	c, err := New(vector.key)
	if err != nil {
		t.Fatal(err)
	}

	ct := append([]byte(nil), vector.ct...)
	ct = append(ct, vector.tag...)
	ct[len(ct)-1] ^= 1

	dst := make([]byte, len(ct))
	for i := range dst {
		dst[i] = 42
	}

	res, err := c.Open(dst[:0], vector.nonce, ct, vector.ad)
	if err == nil {
		t.Fatal("Bad Open still resulted in nil error.")
	}

	if res != nil {
		t.Fatal("Failed Open returned non-nil result.")
	}

	for i := range dst[:len(res)] {
		if dst[i] != 0 {
			t.Fatal("Failed Open didn't zero dst buffer")
		}
	}
}
