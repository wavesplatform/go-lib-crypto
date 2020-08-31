package wavesplatform

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
	"strings"

	"golang.org/x/crypto/ed25519" // "github.com/agl/ed25519"
	"github.com/agl/ed25519/edwards25519"
	"github.com/mr-tron/base58"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

// Bytes is a type alias for the slice of bytes.
type Bytes []byte

// PublicKey is a string representation of a public key bytes in form of BASE58 string.
type PublicKey string

// PrivateKey is a string representation of a private key in form of BASE58 string.
type PrivateKey string

// Seed is a BIP39 seed phrase.
type Seed string

// Address is a string representation of Waves address in form of BASE58 string.
type Address string

// KeyPair is an interface to a structure that holds corresponding private and public keys.
type KeyPair struct {
	PublicKey  PublicKey
	PrivateKey PrivateKey
}

// WavesChainID is a byte to represent blockchain identification.
type WavesChainID byte

// Known chain IDs
const (
	MainNet WavesChainID = 'W'
	TestNet WavesChainID = 'T'
)

// The lengths of basic crypto primitives.
const (
	PublicKeyLength  = 32
	PrivateKeyLength = 32
	DigestLength     = 32
	SignatureLength  = 64

	addressVersion byte = 0x01
	headerSize          = 2
	bodySize            = 20
	checksumSize        = 4
	addressSize         = headerSize + bodySize + checksumSize
	seedBitSize         = 160
	seedWordsCount      = 15
)

// WavesCrypto is a collection of functions to work with Waves basic types and crypto primitives used by Waves.
type WavesCrypto interface {
	Blake2b(input Bytes) Bytes // Blake2b produces the BLAKE2b-256 digest of the given `input`.
	Keccak(input Bytes) Bytes  // Keccak creates a new legacy Keccak-256 hash digest of the `input`.
	Sha256(input Bytes) Bytes  // Sha256 returns a new SHA256 checksum calculated from the `input`.

	Base58Encode(input Bytes) string // Base58Encode encodes the `input` into a BASE58 string.
	Base58Decode(input string) Bytes // Base58Decode decodes the `input` string to bytes.
	Base64Encode(input Bytes) string // Base64Encode returns a BASE64 string representation of the `input` bytes.
	Base64Decode(input string) Bytes // Base64Decode decodes the `input` BASE64 string to bytes.

	KeyPair(seed Seed) KeyPair       // KeyPair returns a pair of keys produced from the `seed`.
	PublicKey(seed Seed) PublicKey   // PublicKey returns a public key generated from the `seed`.
	PrivateKey(seed Seed) PrivateKey // PrivateKey generates a private key from the given `seed`.

	Address(publicKey PublicKey, chainID WavesChainID) Address // Address generates new Waves address from the `publicKey` and `chainID`.
	AddressFromSeed(seed Seed, chainID WavesChainID) Address   // AddressFromSeed returns a new Waves address produced from the `seed` and `chainID`.

	RandomSeed() Seed          // RandomSeed return a new randomly generated BIP39 seed phrase.
	VerifySeed(seed Seed) bool // Checks the seed parameters

	SignBytes(bytes Bytes, privateKey PrivateKey) Bytes // SignBytes produces a signature for the `bytes` by `privateKey`.
	SignBytesBySeed(bytes Bytes, seed Seed) Bytes       // SignBytesBySeed returns a signature for the `bytes` by a private keys generated from the `seed`.~``

	VerifySignature(publicKey PublicKey, bytes, signature Bytes) bool // VerifySignature returns true if `signature` is a valid signature of `bytes` by `publicKey`.

	VerifyAddress(address Address, chainID WavesChainID) bool // VerifyAddress returns true if `address` is a valid Waves address for the given `chainId`. Function calls the `VerifyAddressChecksum` function.
	VerifyAddressChecksum(address Address) bool               // VerifyAddressChecksum calculates and compares the `address` checksum. Returns `true` if the checksum is correct.
}

type crypto struct {
	blake  hash.Hash
	keccak hash.Hash
}

// NewWavesCrypto returns a new instance of WavesCrypto interface.
func NewWavesCrypto() WavesCrypto {
	h1, err := blake2b.New256(nil)
	// An error happens only if the passed array is bigger then the hash size. Here we pass empty array so the error is impossible.
	if err != nil {
		panic(err)
	}
	h2 := sha3.NewLegacyKeccak256()
	return &crypto{
		blake:  h1,
		keccak: h2,
	}
}

// Blake2b function produces the BLAKE2b-256 digest of the given `input` bytes.
// In case of an error the function will panic.
func (c *crypto) Blake2b(input Bytes) Bytes {
	result := make([]byte, DigestLength)
	c.blake.Reset()
	c.blake.Write(input)
	c.blake.Sum(result[:0])
	return result
}

// Keccak function creates a legacy Keccak-256 hash digest of the `input` bytes.
func (c *crypto) Keccak(input Bytes) Bytes {
	result := make([]byte, DigestLength)
	c.keccak.Reset()
	c.keccak.Write(input)
	c.keccak.Sum(result[:0])
	return result
}

// Sha256 return SHA256 digest calculated of the `input`.
func (c *crypto) Sha256(input Bytes) Bytes {
	result := make([]byte, DigestLength)
	h := sha256.New()
	h.Write(input)
	h.Sum(result[:0])
	return result
}

// Base58Encode returns the `input` bytes encoded as BASE58 string.
func (c *crypto) Base58Encode(input Bytes) string {
	return base58.Encode(input)
}

// Base58Decode decodes the `input` string into slice of bytes. Invalid input will be decoded to nil slice of bytes.
func (c *crypto) Base58Decode(input string) Bytes {
	b, err := base58.Decode(input)
	if err != nil {
		return nil
	}
	return b
}

// Base64Encode returns a BASE64 string representation of the `input` bytes.
func (c *crypto) Base64Encode(input Bytes) string {
	return base64.StdEncoding.EncodeToString(input)
}

// Base64Decode decodes the `input` BASE64 string to bytes. Invalid input will result in nil slice of bytes.
func (c *crypto) Base64Decode(input string) Bytes {
	b, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return nil
	}
	return b
}

// KeyPair returns a pair of keys produced from the `seed`.
func (c *crypto) KeyPair(seed Seed) KeyPair {
	sk, pk := c.generateKeyPair(string(seed))
	return KeyPair{
		PrivateKey: PrivateKey(base58.Encode(sk)),
		PublicKey:  PublicKey(base58.Encode(pk)),
	}
}

// PublicKey returns a public key generated from the `seed`.
func (c *crypto) PublicKey(seed Seed) PublicKey {
	return c.KeyPair(seed).PublicKey
}

// PrivateKey generates a private key from the given `seed`.
func (c *crypto) PrivateKey(seed Seed) PrivateKey {
	return c.KeyPair(seed).PrivateKey
}

// Address generates new Waves address from the `publicKey` and `chainID`. The function returns an empty string in case of error.
func (c *crypto) Address(publicKey PublicKey, chainID WavesChainID) Address {
	pk, err := base58.Decode(string(publicKey))
	if err != nil {
		return ""
	}
	return Address(base58.Encode(c.addressBytesFromPK(byte(chainID), pk)))
}

// AddressFromSeed returns a new Waves address produced from the `seed` and `chainID`.
func (c *crypto) AddressFromSeed(seed Seed, chainID WavesChainID) Address {
	_, pk := c.generateKeyPair(string(seed))
	return Address(base58.Encode(c.addressBytesFromPK(byte(chainID), pk)))
}

// RandomSeed return a new randomly generated BIP39 seed phrase.
func (c *crypto) RandomSeed() Seed {
	// The errors are possible only in case of incorrect bits size of entropy, in our case the bits size is defined by constant.
	entropy, err := bip39.NewEntropy(seedBitSize)
	if err != nil {
		panic(err)
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		panic(err)
	}
	return Seed(mnemonic)
}

// SignBytes produces a signature for the `bytes` by `privateKey`.
func (c *crypto) SignBytes(bytes Bytes, privateKey PrivateKey) Bytes {
	privateKeyBytes := c.Base58Decode(string(privateKey))
	var edPubKeyPoint edwards25519.ExtendedGroupElement
	sk := new([DigestLength]byte)
	copy(sk[:], privateKeyBytes[:DigestLength])
	edwards25519.GeScalarMultBase(&edPubKeyPoint, sk)
	edPubKey := new([DigestLength]byte)
	edPubKeyPoint.ToBytes(edPubKey)
	signBit := edPubKey[31] & 0x80
	s := c.sign(sk, edPubKey[:], bytes)
	s[63] &= 0x7f
	s[63] |= signBit
	return Bytes(s[:SignatureLength])
}

// SignBytesBySeed returns a signature for the `bytes` by a private keys generated from the `seed`.
func (c *crypto) SignBytesBySeed(bytes Bytes, seed Seed) Bytes {
	sk := c.PrivateKey(seed)
	return c.SignBytes(bytes, sk)
}

// VerifySignature returns true if `signature` is a valid signature of `bytes` message signed by `publicKey` key.
func (c *crypto) VerifySignature(publicKey PublicKey, bytes, signature Bytes) bool {
	publicKeyBytes := c.Base58Decode(string(publicKey))
	if len(publicKeyBytes) != DigestLength {
		return false
	}
	if len(signature) != SignatureLength {
		return false
	}
	pk := new([DigestLength]byte)
	copy(pk[:], publicKeyBytes[:DigestLength])

	var montX = new(edwards25519.FieldElement)
	edwards25519.FeFromBytes(montX, pk)

	var one = new(edwards25519.FieldElement)
	edwards25519.FeOne(one)
	var montXMinusOne = new(edwards25519.FieldElement)
	edwards25519.FeSub(montXMinusOne, montX, one)
	var montXPlusOne = new(edwards25519.FieldElement)
	edwards25519.FeAdd(montXPlusOne, montX, one)
	var invMontXPlusOne = new(edwards25519.FieldElement)
	edwards25519.FeInvert(invMontXPlusOne, montXPlusOne)
	var edY = new(edwards25519.FieldElement)
	edwards25519.FeMul(edY, montXMinusOne, invMontXPlusOne)

	var edPubKey = new([DigestLength]byte)
	edwards25519.FeToBytes(edPubKey, edY)

	edPubKey[31] &= 0x7F
	edPubKey[31] |= signature[63] & 0x80

	s := new([SignatureLength]byte)
	copy(s[:], signature[:])
	s[63] &= 0x7f

	return ed25519.Verify(edPubKey, bytes, s)
}

// VerifyAddressChecksum returns true if `address` has a valid checksum.
func (c *crypto) VerifyAddressChecksum(address Address) bool {
	ab := c.Base58Decode(string(address))
	if len(ab) != addressSize {
		return false
	}
	if ab[0] != addressVersion {
		return false
	}
	cs := c.secureHash(ab[:headerSize+bodySize])
	return bytes.Equal(ab[headerSize+bodySize:addressSize], cs[:checksumSize])
}

// VerifyAddress returns true if `address` is a valid Waves address for the given `chainID`.
func (c *crypto) VerifyAddress(address Address, chainID WavesChainID) bool {
	ab := c.Base58Decode(string(address))
	if len(ab) != addressSize {
		return false
	}
	if ab[0] != addressVersion || ab[1] != byte(chainID) {
		return false
	}
	cs := c.secureHash(ab[:headerSize+bodySize])
	return bytes.Equal(ab[headerSize+bodySize:addressSize], cs[:checksumSize])
}

// VerifySeed checks the seed for correctness of its properties. Returns true if the seed has 15 words length and contains only words from the dictionary, otherwise returns false.
func (c *crypto) VerifySeed(seed Seed) bool {
	str := string(seed)
	words := strings.Fields(str)
	return len(words) == seedWordsCount && bip39.IsMnemonicValid(str)
}

func (c *crypto) generateSecretKey(seed []byte) []byte {
	sk := make([]byte, PrivateKeyLength)
	copy(sk, seed[:PrivateKeyLength])
	sk[0] &= 248
	sk[31] &= 127
	sk[31] |= 64
	return sk
}

func (c *crypto) generatePublicKey(sk []byte) []byte {
	pk := make([]byte, PublicKeyLength)
	s := new([PrivateKeyLength]byte)
	copy(s[:], sk[:PrivateKeyLength])
	var ed edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&ed, s)
	var edYPlusOne = new(edwards25519.FieldElement)
	edwards25519.FeAdd(edYPlusOne, &ed.Y, &ed.Z)
	var oneMinusEdY = new(edwards25519.FieldElement)
	edwards25519.FeSub(oneMinusEdY, &ed.Z, &ed.Y)
	var invOneMinusEdY = new(edwards25519.FieldElement)
	edwards25519.FeInvert(invOneMinusEdY, oneMinusEdY)
	var montX = new(edwards25519.FieldElement)
	edwards25519.FeMul(montX, edYPlusOne, invOneMinusEdY)
	p := new([PublicKeyLength]byte)
	edwards25519.FeToBytes(p, montX)
	copy(pk[:], p[:])
	return pk
}

func (c *crypto) generateKeyPair(seed string) ([]byte, []byte) {
	s := make([]byte, len(seed)+4)
	copy(s[4:], []byte(seed))
	sh := c.secureHash(s)
	digest := make([]byte, DigestLength)
	h := sha256.New()
	h.Write(sh)
	h.Sum(digest[:0])
	sk := c.generateSecretKey(digest)
	pk := c.generatePublicKey(sk)
	return sk, pk
}

func (c *crypto) secureHash(data []byte) []byte {
	result := make([]byte, DigestLength)
	c.blake.Reset()
	c.keccak.Reset()
	c.blake.Write(data)
	c.blake.Sum(result[:0])
	c.keccak.Write(result)
	return c.keccak.Sum(result[:0])
}

func (c *crypto) addressBytesFromPK(scheme byte, pk []byte) []byte {
	addr := make([]byte, addressSize)
	addr[0] = addressVersion
	addr[1] = scheme
	sh := c.secureHash(pk)
	copy(addr[headerSize:headerSize+bodySize], sh[:bodySize])
	cs := c.secureHash(addr[:headerSize+bodySize])
	copy(addr[headerSize+bodySize:addressSize], cs)

	return addr
}

func (c *crypto) sign(curvePrivateKey *[DigestLength]byte, edPublicKey, data []byte) []byte {
	prefix := bytes.Repeat([]byte{0xff}, 32)
	prefix[0] = 0xfe
	random := make([]byte, 64)
	rand.Read(random)

	var messageDigest, hramDigest [64]byte
	h := sha512.New()
	h.Write(prefix)
	h.Write(curvePrivateKey[:])
	h.Write(data)
	h.Write(random)
	h.Sum(messageDigest[:0])

	var messageDigestReduced [32]byte
	edwards25519.ScReduce(&messageDigestReduced, &messageDigest)
	var R edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&R, &messageDigestReduced)

	var encodedR [32]byte
	R.ToBytes(&encodedR)

	h.Reset()
	h.Write(encodedR[:])
	h.Write(edPublicKey)
	h.Write(data)
	h.Sum(hramDigest[:0])
	var hramDigestReduced [32]byte
	edwards25519.ScReduce(&hramDigestReduced, &hramDigest)

	var s [32]byte
	edwards25519.ScMulAdd(&s, &hramDigestReduced, curvePrivateKey, &messageDigestReduced)

	signature := make([]byte, SignatureLength)
	copy(signature, encodedR[:])
	copy(signature[32:], s[:])
	return signature
}
