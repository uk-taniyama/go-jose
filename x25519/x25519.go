package x25519

import (
	cryptorand "crypto/rand"
	"io"

	"golang.org/x/crypto/curve25519"
)

const (
	// PublicKeySize is the size, in bytes, of public keys as used in this package.
	PublicKeySize = 32
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = 32
)

// PublicKey is the type of X25519 public keys.
type PublicKey []byte

// PrivateKey is the type of X25519 public keys.
type PrivateKey []byte

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (PrivateKey, error) {
	if rand == nil {
		rand = cryptorand.Reader
	}

	privateKey := make([]byte, PrivateKeySize)
	if _, err := io.ReadFull(rand, privateKey); err != nil {
		return nil, err
	}

	return privateKey, nil
}

// Public returns the PublicKey corresponding to priv.
func (priv PrivateKey) Public() (PublicKey, error) {
	return curve25519.X25519(priv, curve25519.Basepoint)
}

// Shared returns the SharedSecretKey corresponding to priv and pub.
func (priv PrivateKey) Shared(pub PublicKey) (PublicKey, error) {
	return curve25519.X25519(priv, pub)
}
