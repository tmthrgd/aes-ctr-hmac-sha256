# aes-ctr-hmac-sha256

[![GoDoc](https://godoc.org/github.com/tmthrgd/aes-ctr-hmac-sha256?status.svg)](https://godoc.org/github.com/tmthrgd/aes-ctr-hmac-sha256)
[![Build Status](https://travis-ci.org/tmthrgd/aes-ctr-hmac-sha256.svg?branch=master)](https://travis-ci.org/tmthrgd/aes-ctr-hmac-sha256)

This is a Golang implementation of [|EVP\_aead\_aes\_128\_ctr\_hmac\_sha256|](https://github.com/google/boringssl/blob/adec7726ecb2cd5e563b864cb292867724adcd18/include/openssl/aead.h#L103-L106) and [|EVP\_aead\_aes\_256\_ctr\_hmac\_sha256|](https://github.com/google/boringssl/blob/adec7726ecb2cd5e563b864cb292867724adcd18/include/openssl/aead.h#L108-L110) from [BoringSSL](https://github.com/google/boringssl/tree/adec7726ecb2cd5e563b864cb292867724adcd18). The C implementation is in [crypto/cipher/e_aes.c](https://github.com/google/boringssl/blob/adec7726ecb2cd5e563b864cb292867724adcd18/crypto/cipher/e_aes.c#L1182-L1447). Unlike BoringSSL, this also supports AES-192-CTR + HMAC-SHA256.

The description of the algorithm, taken from BoringSSL, is:
> |EVP\_aead\_aes\_128\_ctr\_hmac\_sha256| is AES-128 in CTR mode with HMAC-SHA256 for
> authentication. The nonce is 12 bytes; the bottom 32-bits are used as the
> block counter, thus the maximum plaintext size is 64GB.

It really does not make much sense to use this - the performance is terrible for one thing. It is here if anyone has a use for it.

## Download

```
go get github.com/tmthrgd/aes-ctr-hmac-sha256
```

## Benchmark

```
BenchmarkAES128CTRWithHMACSHA256/32-8         	  300000	      3780 ns/op	   8.46 MB/s
BenchmarkAES128CTRWithHMACSHA256/128-8        	  300000	      4241 ns/op	  30.18 MB/s
BenchmarkAES128CTRWithHMACSHA256/1K-8         	  200000	     10576 ns/op	  96.82 MB/s
BenchmarkAES128CTRWithHMACSHA256/16K-8        	   10000	    125610 ns/op	 130.44 MB/s
BenchmarkAES128CTRWithHMACSHA256/128K-8       	    2000	    986370 ns/op	 132.88 MB/s
BenchmarkAES128CTRWithHMACSHA256/1M-8         	     200	   7656672 ns/op	 136.95 MB/s
BenchmarkAES256CTRWithHMACSHA256/32-8         	  300000	      3989 ns/op	   8.02 MB/s
BenchmarkAES256CTRWithHMACSHA256/128-8        	  300000	      5067 ns/op	  25.26 MB/s
BenchmarkAES256CTRWithHMACSHA256/1K-8         	  100000	     11750 ns/op	  87.14 MB/s
BenchmarkAES256CTRWithHMACSHA256/16K-8        	   10000	    132009 ns/op	 124.11 MB/s
BenchmarkAES256CTRWithHMACSHA256/128K-8       	    2000	   1032715 ns/op	 126.92 MB/s
BenchmarkAES256CTRWithHMACSHA256/1M-8         	     200	   8176714 ns/op	 128.24 MB/s
BenchmarkAES128GCM/32-8                       	10000000	       141 ns/op	 226.20 MB/s
BenchmarkAES128GCM/128-8                      	10000000	       166 ns/op	 767.82 MB/s
BenchmarkAES128GCM/1K-8                       	 2000000	       826 ns/op	1238.21 MB/s
BenchmarkAES128GCM/16K-8                      	  100000	     12191 ns/op	1343.91 MB/s
BenchmarkAES128GCM/128K-8                     	   20000	     97370 ns/op	1346.11 MB/s
BenchmarkAES128GCM/1M-8                       	    2000	    937109 ns/op	1118.95 MB/s
BenchmarkAES256GCM/32-8                       	10000000	       181 ns/op	 176.03 MB/s
BenchmarkAES256GCM/128-8                      	10000000	       217 ns/op	 588.52 MB/s
BenchmarkAES256GCM/1K-8                       	 2000000	       924 ns/op	1108.09 MB/s
BenchmarkAES256GCM/16K-8                      	  100000	     13790 ns/op	1188.03 MB/s
BenchmarkAES256GCM/128K-8                     	   10000	    109367 ns/op	1198.46 MB/s
BenchmarkAES256GCM/1M-8                       	    2000	   1042985 ns/op	1005.36 MB/s
BenchmarkChaCha20Poly1305/32-8                	10000000	       192 ns/op	 166.20 MB/s
BenchmarkChaCha20Poly1305/128-8               	10000000	       228 ns/op	 560.54 MB/s
BenchmarkChaCha20Poly1305/1K-8                	 1000000	      1190 ns/op	 860.41 MB/s
BenchmarkChaCha20Poly1305/16K-8               	  100000	     16969 ns/op	 965.51 MB/s
BenchmarkChaCha20Poly1305/128K-8              	   10000	    134881 ns/op	 971.76 MB/s
BenchmarkChaCha20Poly1305/1M-8                	    1000	   1338484 ns/op	 783.41 MB/s
```

## License

Unless otherwise noted, the aes-ctr-hmac-sha256 source files are distributed under the Modified BSD License
found in the LICENSE file.