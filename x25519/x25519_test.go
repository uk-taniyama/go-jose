package x25519_test

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"

	"github.com/go-jose/go-jose/v3/x25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// https://datatracker.ietf.org/doc/html/rfc7748
var (
	// Alice's private key, a:
	alicePriv = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	//   Alice's public key, X25519(a, 9):
	alicePub = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	//   Bob's private key, b:
	bobPriv = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
	//   Bob's public key, X25519(b, 9):
	bobPub = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
	// Their shared secret, K:
	shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
)

func hexReader(input string) io.Reader {
	b, err := hex.DecodeString(input)
	if err != nil {
		panic(err)
	}
	return bytes.NewReader(b)
}

func testGenerateKey(t *testing.T, priv, pub string) (x25519.PrivateKey, x25519.PublicKey) {
	privKey, err := x25519.GenerateKey(hexReader(priv))
	require.NoError(t, err)
	assert.Equal(t, priv, hex.EncodeToString(privKey))

	pubKey, err := privKey.Public()
	require.NoError(t, err)
	assert.Equal(t, pub, hex.EncodeToString(pubKey))

	return privKey, pubKey
}

func testXchange(t *testing.T, privKey x25519.PrivateKey, pubKey x25519.PublicKey, shared string) {
	sharedKey, err := privKey.Shared(pubKey)
	require.NoError(t, err)
	assert.Equal(t, shared, hex.EncodeToString(sharedKey))
}

func TestX25519(t *testing.T) {
	alicePrivKey, alicePubKey := testGenerateKey(t, alicePriv, alicePub)
	bobPrivKey, bobPubKey := testGenerateKey(t, bobPriv, bobPub)

	testXchange(t, alicePrivKey, bobPubKey, shared)
	testXchange(t, bobPrivKey, alicePubKey, shared)
}
