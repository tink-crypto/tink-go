// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package subtle

import (
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	internalaead "github.com/tink-crypto/tink-go/v2/internal/aead"
	"github.com/tink-crypto/tink-go/v2/internal/random"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// ChaCha20Poly1305 is a ChaCha20-Poly1305 implementation of the [tink.AEAD]
// interface.
type ChaCha20Poly1305 struct {
	rawAEAD cipher.AEAD
}

var _ tink.AEAD = (*ChaCha20Poly1305)(nil)

// NewChaCha20Poly1305 returns an [ChaCha20Poly1305] instance.
//
// The key argument must be a 32-bytes key.
func NewChaCha20Poly1305(key []byte) (*ChaCha20Poly1305, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("chacha20_poly1305: bad key length: got %d, want %d", len(key), chacha20poly1305.KeySize)
	}
	rawAEAD, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("chacha20_poly1305: failed to create AEAD, error: %v", err)
	}
	return &ChaCha20Poly1305{rawAEAD: rawAEAD}, nil
}

// Encrypt encrypts plaintext with associatedData.
//
// The resulting ciphertext is of the form: | nonce | ciphertext | tag |.
func (ca *ChaCha20Poly1305) Encrypt(plaintext []byte, associatedData []byte) ([]byte, error) {
	if err := internalaead.CheckChaCha20Poly1305PlaintextSize(len(plaintext)); err != nil {
		return nil, err
	}
	ciphertext := make([]byte, chacha20poly1305.NonceSize, chacha20poly1305.NonceSize+len(plaintext)+chacha20poly1305.Overhead)
	nonce := ciphertext[:chacha20poly1305.NonceSize]
	random.MustRand(nonce)
	return ca.rawAEAD.Seal(ciphertext, nonce, plaintext, associatedData), nil
}

// Decrypt decrypts ciphertext with associatedData.
//
// The ciphertext must be of the form: | nonce | ciphertext | tag |.
func (ca *ChaCha20Poly1305) Decrypt(ciphertext []byte, associatedData []byte) ([]byte, error) {
	if len(ciphertext) < chacha20poly1305.NonceSize+chacha20poly1305.Overhead {
		return nil, fmt.Errorf("chacha20_poly1305: ciphertext too short")
	}
	nonce := ciphertext[:chacha20poly1305.NonceSize]
	ciphertextAndTag := ciphertext[chacha20poly1305.NonceSize:]
	plaintext, err := ca.rawAEAD.Open(nil, nonce, ciphertextAndTag, associatedData)
	if err != nil {
		return nil, fmt.Errorf("chacha20_poly1305: %w", err)
	}
	return plaintext, nil
}
