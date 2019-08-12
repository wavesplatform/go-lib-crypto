package wavesplatform

import (
	"encoding/hex"
	"strings"
	"testing"
)

var c = NewWavesCrypto()

func TestBlake2b(t *testing.T) {
	tests := []struct {
		data     string
		expected string
	}{
		{"00000000000000000000000000000000000000000000000000000000000000", "3421e43b3443c7a7507add317b7c876ed74ec6d580fdac30b1fe8ba382a1b9c7"},
		{"0100000000000000000000000000000000000000000000000000000000000000", "afbc1c053c2f278e3cbd4409c1c094f184aa459dd2f7fca96d6077730ab9ffe3"},
		{"0000000000", "569ed9e4a5463896190447e6ffe37c394c4d77ce470aa29ad762e0286b896832"},
		{"64617461", "a035872d6af8639ede962dfe7536b0c150b590f3234a922fb7064cd11971b58e"},
		{"ffffffffffffffff", "e2d93df6a2e919e879551686bc301480fc50c54dc949b14b916d5834113bb061"},
	}
	for _, tc := range tests {
		data := fromHex(t, tc.data)
		expected := fromHex(t, tc.expected)
		actual := c.Blake2b(data)
		assertBytes(t, expected, actual)
	}
}

func TestKeccak(t *testing.T) {
	tests := []struct {
		data     string
		expected string
	}{
		{"00000000000000000000000000000000000000000000000000000000000000", "15fed0451499512d95f3ec5a41c878b9de55f21878b5b4e190d4667ec709b4cf"},
		{"0100000000000000000000000000000000000000000000000000000000000000", "48078cfed56339ea54962e72c37c7f588fc4f8e5bc173827ba75cb10a63a96a5"},
		{"0000000000", "c41589e7559804ea4a2080dad19d876a024ccb05117835447d72ce08c1d020ec"},
		{"64617461", "8f54f1c2d0eb5771cd5bf67a6689fcd6eed9444d91a39e5ef32a9b4ae5ca14ff"},
		{"ffffffffffffffff", "ad0bfb4b0a66700aeb759d88c315168cc0a11ee99e2a680e548ecf0a464e7daf"},
	}
	for _, tc := range tests {
		data := fromHex(t, tc.data)
		expected := fromHex(t, tc.expected)
		actual := c.Keccak(data)
		assertBytes(t, expected, actual)
	}
}

func TestSha256(t *testing.T) {
	tests := []struct {
		data     string
		expected string
	}{
		{"00000000000000000000000000000000000000000000000000000000000000", "fd08be957bda07dc529ad8100df732f9ce12ae3e42bcda6acabe12c02dfd6989"},
		{"0100000000000000000000000000000000000000000000000000000000000000", "01d0fabd251fcbbe2b93b4b927b26ad2a1a99077152e45ded1e678afa45dbec5"},
		{"0000000000", "8855508aade16ec573d21e6a485dfd0a7624085c1a14b5ecdd6485de0c6839a4"},
		{"64617461", "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"},
		{"ffffffffffffffff", "12a3ae445661ce5dee78d0650d33362dec29c4f82af05e7e57fb595bbbacf0ca"},
	}
	for _, tc := range tests {
		data := fromHex(t, tc.data)
		expected := fromHex(t, tc.expected)
		actual := c.Sha256(data)
		assertBytes(t, expected, actual)
	}
}

func TestBase58Encoding(t *testing.T) {
	tests := []struct {
		data     string
		expected string
	}{
		{"fd08be957bda07dc529ad8100df732f9ce12ae3e42bcda6acabe12c02dfd6989", "J2jt7JvkLC4GnJ9HY5osKLYxabjpUG5ND3uaS8SY7ybv"},
		{"0100000000000000000000000000000000000000000000000000000000000000", "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM"},
		{"0000000000", "11111"},
		{"64617461", "3ZpVkU"},
		{"ffffffffffffffff", "jpXCZedGfVQ"},
	}
	for _, tc := range tests {
		data := fromHex(t, tc.data)
		actual := c.Base58Encode(data)
		assertStrings(t, tc.expected, actual)
	}
}

func TestBase58Decoding(t *testing.T) {
	tests := []struct {
		str      string
		expected string
	}{
		{"J2jt7JvkLC4GnJ9HY5osKLYxabjpUG5ND3uaS8SY7ybv", "fd08be957bda07dc529ad8100df732f9ce12ae3e42bcda6acabe12c02dfd6989"},
		{"4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM", "0100000000000000000000000000000000000000000000000000000000000000"},
		{"11111", "0000000000"},
		{"3ZpVkU", "64617461"},
		{"jpXCZedGfVQ", "ffffffffffffffff"},
		{"", ""},
		{"invalid BASE58 string", ""},
	}
	for _, tc := range tests {
		expected := fromHex(t, tc.expected)
		actual := c.Base58Decode(tc.str)
		assertBytes(t, expected, actual)
	}
}

func TestBase64Encoding(t *testing.T) {
	tests := []struct {
		data     string
		expected string
	}{
		{"fd08be957bda07dc529ad8100df732f9ce12ae3e42bcda6acabe12c02dfd6989", "/Qi+lXvaB9xSmtgQDfcy+c4Srj5CvNpqyr4SwC39aYk="},
		{"0100000000000000000000000000000000000000000000000000000000000000", "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
		{"0000000000", "AAAAAAA="},
		{"64617461", "ZGF0YQ=="},
		{"ffffffffffffffff", "//////////8="},
	}
	for _, tc := range tests {
		data := fromHex(t, tc.data)
		actual := c.Base64Encode(data)
		if actual != tc.expected {
			t.Fatalf("Actual value not equal to expected:\nExpected: %s\nActual..: %s", tc.expected, actual)
		}
	}
}

func TestBase64Decoding(t *testing.T) {
	tests := []struct {
		str      string
		expected string
	}{
		{"/Qi+lXvaB9xSmtgQDfcy+c4Srj5CvNpqyr4SwC39aYk=", "fd08be957bda07dc529ad8100df732f9ce12ae3e42bcda6acabe12c02dfd6989"},
		{"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "0100000000000000000000000000000000000000000000000000000000000000"},
		{"AAAAAAA=", "0000000000"},
		{"ZGF0YQ==", "64617461"},
		{"//////////8=", "ffffffffffffffff"},
		{"", ""},
		{"invalid BASE64 string", ""},
	}
	for _, tc := range tests {
		expected := fromHex(t, tc.expected)
		actual := c.Base64Decode(tc.str)
		assertBytes(t, expected, actual)
	}
}

func TestKeyGeneration(t *testing.T) {
	tests := []struct {
		seed       Seed
		expectedSK PrivateKey
		expectedPK PublicKey
	}{
		{"shuffle avoid clever page hidden divorce charge derive arrow maximum warfare travel author message orient", "EWi5qaq7fLziXPAbVom7JQcg2GhU9LDC67xtrUDvX5uz", "5TmrbLz3J9jtAtnCHXgXzxw8i3EgM2t5kELL3ShaVFk3"},
		{"net push clap barrel border blood drip clog apart rule message victory snack author uncle", "4mqdzd3jPGY7gxr9swdNoUtM3T1ex9c6J9L6hRqZtgTG", "GMm3hnBGU2FACB77Ze49ooFPMmYiKqeuQkVFhbVXCstn"},
		{"gentle injury glad surround broom develop weather health silk glimpse castle riot mango team material", "3A2AJLd2MEaPTnrnnArUrmppeznASdVgCnL8UomXdcxW", "CoJWXA5kocLGUJxhvp6qKufhKMaHsqww2CuEm1TqtLi7"},
		{"reward pony cheap client marriage round planet future scorpion student motor rebel announce repair few", "F3z7cLrDwPKx1icN6sXGAdv2KXuhiuhYJVQqJZJfSrmC", "2rAsTn3hTwQKJkbAvgQ9FvBgBoBRpPSkDcNcm39aDacs"},
		{"razor valley junk regret daring room skate deny into mask daughter session bullet please differ", "6xXRDfY2pNxGSgT3mdiaUgCZXfPR8vXikjraDMvXhHHi", "ANaV6NCdB4vSZy3jYUSMbKUQvKHQH77D7fTqyRHYkFVW"},
	}
	for _, tc := range tests {
		pair := c.KeyPair(tc.seed)
		sk := c.PrivateKey(tc.seed)
		if pair.PrivateKey != sk {
			t.Fatalf("Different private key '%s', key pair has '%s'", sk, pair.PrivateKey)
		}
		pk := c.PublicKey(tc.seed)
		if pair.PublicKey != pk {
			t.Fatalf("Different public key '%s', key pair has '%s'", pk, pair.PublicKey)
		}
		assertStrings(t, string(tc.expectedSK), string(sk))
		assertStrings(t, string(tc.expectedPK), string(pk))
	}
}

func TestAddress(t *testing.T) {
	tests := []struct {
		pk       PublicKey
		expected Address
	}{
		{"5TmrbLz3J9jtAtnCHXgXzxw8i3EgM2t5kELL3ShaVFk3", "3PLfT4PAh1XfPQpRQwT4HSA3rjFoTbNukaE"},
		{"GMm3hnBGU2FACB77Ze49ooFPMmYiKqeuQkVFhbVXCstn", "3PJWCeymumZzVfuhx8ZatCBPb8d2BZMA6u1"},
		{"CoJWXA5kocLGUJxhvp6qKufhKMaHsqww2CuEm1TqtLi7", "3P92gW8nBYSBn9JAGshRASxawKiKJUwqqxq"},
		{"2rAsTn3hTwQKJkbAvgQ9FvBgBoBRpPSkDcNcm39aDacs", "3P5CHxJ2HjQk9efEGPoznavZ39JhG6wgatS"},
		{"ANaV6NCdB4vSZy3jYUSMbKUQvKHQH77D7fTqyRHYkFVW", "3P3cCtmag4bL11wg9grrGseNhp1Q9ocsPzy"},
		{"ANaV6NCdB4vSZy3jYUSMbKUQvKHQH77D7fTqyRHYkIVW", ""},
	}
	for _, tc := range tests {
		a := c.Address(tc.pk, 'W')
		assertStrings(t, string(tc.expected), string(a))
		assertStrings(t, string(tc.expected), string(a))
	}
}

func TestAddressFromSeed(t *testing.T) {
	tests := []struct {
		seed     Seed
		expected Address
	}{
		{"shuffle avoid clever page hidden divorce charge derive arrow maximum warfare travel author message orient", "3PLfT4PAh1XfPQpRQwT4HSA3rjFoTbNukaE"},
		{"net push clap barrel border blood drip clog apart rule message victory snack author uncle", "3PJWCeymumZzVfuhx8ZatCBPb8d2BZMA6u1"},
		{"gentle injury glad surround broom develop weather health silk glimpse castle riot mango team material", "3P92gW8nBYSBn9JAGshRASxawKiKJUwqqxq"},
		{"reward pony cheap client marriage round planet future scorpion student motor rebel announce repair few", "3P5CHxJ2HjQk9efEGPoznavZ39JhG6wgatS"},
		{"razor valley junk regret daring room skate deny into mask daughter session bullet please differ", "3P3cCtmag4bL11wg9grrGseNhp1Q9ocsPzy"},
	}
	for _, tc := range tests {
		a := c.AddressFromSeed(tc.seed, 'W')
		assertStrings(t, string(tc.expected), string(a))
		assertStrings(t, string(tc.expected), string(a))
	}
}

func TestVerifyAddressChecksum(t *testing.T) {
	tests := []struct {
		address  Address
		expected bool
	}{
		{"3PLfT4PAh1XfPQpRQwT4HSA3rjFoTbNukaE", true},
		{"3MxyKNmnQkVuDCG9AzMpixKCdUWXfMUsxdg", true},
		{"2P92gW8nBYSBn9JAGshRASxawKiKJUwqqxq", false},
		{"3P5CHxJ2HjQk9efEGPoznavZ39JhG6wga", false},
		{"3P3cCtmag4bL11wg9grrGseNhp1Q8ocsPzy", false},
		{"5A48cxZtRpmxJNuNKxG7s1k46w9McoaCeyF", false},
	}
	for _, tc := range tests {
		ok := c.VerifyAddressChecksum(tc.address)
		if ok != tc.expected {
			t.Fatalf("Unexpected result '%v', expected '%v'", ok, tc.expected)
		}
	}
}

func TestVerifyAddress(t *testing.T) {
	tests := []struct {
		address  Address
		chainID  WavesChainID
		expected bool
	}{
		{"3PLfT4PAh1XfPQpRQwT4HSA3rjFoTbNukaE", 'W', true},
		{"3MxyKNmnQkVuDCG9AzMpixKCdUWXfMUsxdg", 'T', true},
		{"3P92gW8nBYSBn9JAGshRASxawKiKJUwqqxq", 'T', false},
		{"3P5CHxJ2HjQk9efEGPoznavZ39JhG6wga", 'W', false},
		{"3P3cCtmag4bL11wg9grrGseNhp1Q8ocsPzy", 'W', false},
		{"5A48cxZtRpmxJNuNKxG7s1k46w9McoaCeyF", 'W', false},
		{"3N9Q2drEHLj5XVNuo1cphYMq4jBN7qoKW6e", 'T', true},
	}
	for _, tc := range tests {
		ok := c.VerifyAddress(tc.address, tc.chainID)
		if ok != tc.expected {
			t.Fatalf("Unexpected result '%v', expected '%v'", ok, tc.expected)
		}
	}
}

func TestRandomSeed(t *testing.T) {
	for i := 0; i < 10; i++ {
		seed := c.RandomSeed()
		words := strings.Fields(string(seed))
		if l := len(words); l != seedWordsCount {
			t.Fatalf("Unexpected number of words in seed phrase %d, expected %d", l, seedWordsCount)
		}
		ok := c.VerifySeed(seed)
		if !ok {
			t.Fatal("Invalid seed phrase")
		}
	}
}

func TestSignVerify(t *testing.T) {
	tests := []struct {
		seed    Seed
		message string
	}{
		{"shuffle avoid clever page hidden divorce charge derive arrow maximum warfare travel author message orient", "fd08be957bda07dc529ad8100df732f9ce12ae3e42bcda6acabe12c02dfd6989"},
		{"net push clap barrel border blood drip clog apart rule message victory snack author uncle", "54686973206973206120746573742074657874206d65737361676520746f206265207369676e656420616e642076657269666965642e"},
		{"gentle injury glad surround broom develop weather health silk glimpse castle riot mango team material", "0000000000"},
		{"reward pony cheap client marriage round planet future scorpion student motor rebel announce repair few", "64617461"},
		{"razor valley junk regret daring room skate deny into mask daughter session bullet please differ", "ffffffffffffffff"},
		{"razor valley junk regret daring room skate deny into mask daughter session bullet please differ", ""},
	}
	for _, tc := range tests {
		pair := c.KeyPair(tc.seed)
		message := fromHex(t, tc.message)
		sig := c.SignBytes(message, pair.PrivateKey)
		if len(sig) == 0 {
			t.Fatal("Empty signature")
		}
		ok := c.VerifySignature(pair.PublicKey, message, sig)
		if !ok {
			t.Fatal("Failed to verify signed data")
		}
	}
}

func TestSignBySeedAndVerify(t *testing.T) {
	tests := []struct {
		seed    Seed
		message string
	}{
		{"shuffle avoid clever page hidden divorce charge derive arrow maximum warfare travel author message orient", "fd08be957bda07dc529ad8100df732f9ce12ae3e42bcda6acabe12c02dfd6989"},
		{"net push clap barrel border blood drip clog apart rule message victory snack author uncle", "54686973206973206120746573742074657874206d65737361676520746f206265207369676e656420616e642076657269666965642e"},
		{"gentle injury glad surround broom develop weather health silk glimpse castle riot mango team material", "0000000000"},
		{"reward pony cheap client marriage round planet future scorpion student motor rebel announce repair few", "64617461"},
		{"razor valley junk regret daring room skate deny into mask daughter session bullet please differ", "ffffffffffffffff"},
		{"razor valley junk regret daring room skate deny into mask daughter session bullet please differ", ""},
	}
	for _, tc := range tests {
		pk := c.PublicKey(tc.seed)
		message := fromHex(t, tc.message)
		sig := c.SignBytesBySeed(message, tc.seed)
		if len(sig) == 0 {
			t.Fatal("Empty signature")
		}
		ok := c.VerifySignature(pk, message, sig)
		if !ok {
			t.Fatal("Failed to verify signed data")
		}
	}
}

func TestVerify(t *testing.T) {
	tests := []struct {
		pk        PublicKey
		message   string
		signature string
		expected  bool
	}{
		{"5TmrbLz3J9jtAtnCHXgXzxw8i3EgM2t5kELL3ShaVFk3", "fd08be957bda07dc529ad8100df732f9ce12ae3e42bcda6acabe12c02dfd6989", "e280dde6cb084190bffa97198487585f4d39d3f862ff1cdf192eb1ab1af2d9456077a96d6ea7db2aa2c787326b7587a05859751e5defaa402f8cb97034c5320b", true},
		{"GMm3hnBGU2FACB77Ze49ooFPMmYiKqeuQkVFhbVXCstn", "54686973206973206120746573742074657874206d65737361676520746f206265207369676e656420616e642076657269666965642e", "e25afd2a680d63bd0d8f64aaa0e62e3e581c266cbf8d74180f20342007625bf749a6f68f26c1873ef8b7f0e22b4432c3cf7d6d785f8b8e065868576ef2876f0e", true},
		{"CoJWXA5kocLGUJxhvp6qKufhKMaHsqww2CuEm1TqtLi7", "0000000000", "", false},
		{"2rAsTn3hTwQKJkbAvgQ9FvBgBoBRpPSkDcNcm39aDacs", "64617461", "ba2229fabf6644448a89ced42feb0e728e4459845fc7acb11ec103ef6eaa3894e962b939009966c1c9d32286ffe188b569b4486bfcb6da1179ee4468e2ac5f86", false},
		{"ANaV6NCdB4vSZy3jYUSMbKUQvKHQH77D7fTqyRHYkFVW", "ffffffffffffffff", "272dcc2fca66b39b23d89014465b10462793f93e8abd465528b54435a51e0d6a9e1948b4cff2cc386f343a7e27ce934453e983005162800cf15ab59f14a9f48d", true},
		{"aV6NCdB4vSZy3jYUSMbKUQvKHQH77D7fTqyRHYkFVW", "ffffffffffffffff", "272dcc2fca66b39b23d89014465b10462793f93e8abd465528b54435a51e0d6a9e1948b4cff2cc386f343a7e27ce934453e983005162800cf15ab59f14a9f48d", false},
	}
	for _, tc := range tests {
		message := fromHex(t, tc.message)
		signature := fromHex(t, tc.signature)
		actual := c.VerifySignature(tc.pk, message, signature)
		if actual != tc.expected {
			t.Fatalf("Actual verification result '%v' is differ from the expected '%v'", actual, tc.expected)
		}
	}
}

func assertBytes(t *testing.T, expected, actual Bytes) {
	if len(expected) != len(actual) {
		t.Fatalf("Length of expected Bytes (%d) is different from the length of actual Bytes (%d):\nExpected: %s\nActual..: %s", len(expected), len(actual), logBytes(expected), logBytes(actual))
	}
	for i := 0; i < len(actual); i++ {
		if expected[i] != actual[i] {
			t.Fatalf("Actual value is different at position %d from the expected:\nExpected: %s\nActual..: %s\n          %s", i, logBytes(expected), logBytes(actual), highlight(i))
		}
	}
}

func assertStrings(t *testing.T, expected, actual string) {
	if actual != expected {
		t.Fatalf("Actual value not equal to expected:\nExpected: %s\nActual..: %s", expected, actual)
	}
}

func logBytes(bytes Bytes) string {
	return spread(hex.EncodeToString(bytes))
}

func spread(s string) string {
	b := []byte(s)
	l := len(b) / 2
	for i := 1; i < l; i++ {
		b = append(b, 0)
		k := i*2 + i - 1
		copy(b[k+1:], b[k:])
		b[k] = ' '
	}
	return string(b)
}

func highlight(pos int) string {
	sb := strings.Builder{}
	for i := 0; i < pos; i++ {
		sb.WriteString("   ")
	}
	sb.WriteString("^^")
	return sb.String()
}

func fromHex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	return b
}
