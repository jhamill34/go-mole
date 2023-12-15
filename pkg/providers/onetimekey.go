package providers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"golang.org/x/crypto/ssh"
)

type OneTimeKeyProvider struct {
	public  []byte
	private []byte
}

// GenerateKey implements services.KeyGen.
func NewStaticKeyProvider() *OneTimeKeyProvider {
	return &OneTimeKeyProvider{}
}

// RetireveKey implements services.KeyProvider.
func (self *OneTimeKeyProvider) RetireveKey() ([]byte, []byte) {
	if self.private == nil || self.public == nil {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		priv := pem.EncodeToMemory(&pem.Block{
			Type:    "RSA PRIVATE KEY",
			Headers: nil,
			Bytes:   privateKeyBytes,
		})

		publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
		if err != nil {
			panic(err)
		}
		pub := ssh.MarshalAuthorizedKey(publicKey)

		self.public = pub
		self.private = priv
	}

	return self.public, self.private
}


