# go-lib-crypto

[![Go Report Card](https://goreportcard.com/badge/github.com/wavesplatform/go-lib-crypto)](https://goreportcard.com/report/github.com/wavesplatform/go-lib-crypto)
[![GoDoc](https://godoc.org/github.com/wavesplatform/go-lib-crypto?status.svg)](https://godoc.org/github.com/wavesplatform/go-lib-crypto)

`go-lib-crypto` is a unified crypto library for [Waves Platform](https://wavesplatform.com). It has a unified set of functions corresponding with [`unified-declarations`](https://github.com/wavesplatform/unified-declarations).

This library meant to be used in client applications. That's why its API is relatively simple. 

The following could be done using the library:

* Calculation of a hash digest of various hash functions used by Waves
* Encoding and decoding of byte slices in BASE58 and BASE64 string representation
* Key pair generation from seed phrase
* Waves address generation and verification
* Random seed phrase generation and verification
* Signing of bytes message
* Verification of signed message

## Installation and import

```bash
go get -u github.com/wavesplatform/go-lib-crypto
```
```go
import "github.com/wavesplatform/go-lib-crypto"
```

## Short API reference with examples

### Instantiation

For the purpose of unification the API of the library made in form of the interface.
To instantiate the un-exported structure that implements the interface call the `NewWavesCrypto` function.

```go
crypto := wavesplatform.NewWavesCrypto()
```

### Working with hashes

The three hash functions used by Waves are supported:

* SHA-256
* BLAKE2b-256
* Keccak-256 (legacy version)

Every hash functions accepts one parameter of type `Bytes`. The `Bytes` type wraps a slice of bytes.

```go
package main

import (
	"encoding/hex"
	"fmt"
	"github.com/wavesplatform/go-lib-crypto"
)

func main() {
	bytes, _ := hex.DecodeString("fd08be957bda07dc529ad8100df732f9ce12ae3e42bcda6acabe12c02dfd6989")
	c := wavesplatform.NewWavesCrypto()
	blake := c.Blake2b(bytes)
	keccak := c.Keccak(bytes)
	sha := c.Sha256(bytes)
	fmt.Println("BLAKE2b-256:", hex.EncodeToString(blake))
	fmt.Println("Keccak-256:", hex.EncodeToString(keccak))
	fmt.Println("SHA-256:", hex.EncodeToString(sha))
}
```

The output should be like this:

```
BLAKE2b-256: c425f69e3be14c929d18b2808831cbaeb2733c9e6b9c5ed37c3601086f202396
Keccak-256: 14a0d0ee74865d8d721c4218768b7c39fd365b53f0359d6d28d82dc97450f583
SHA-256: 7ed1b5b6867c0d6c98097676adc00b6049882e473441ac5ff3613df48b69f9f3
```

### Keys generation

One can create a new key pair from the seed phrase. Library defines types for `Seed`, `PrivateKey`, `PublicKey` (wrappers over `string`) and structure for `KeyPair` that combines the private and public keys.



## Documentation

["`go-lib-crypto` on GoDoc"](http://godoc.org/github.com/wavesplatform/go-lib-crypto).