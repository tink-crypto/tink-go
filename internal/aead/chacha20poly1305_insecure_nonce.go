// Copyright 2022 Google LLC
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

package aead

import (
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// ChaCha20Poly1305InsecureNonceSize is the size of the nonce.
	ChaCha20Poly1305InsecureNonceSize = chacha20poly1305.NonceSize
	// ChaCha20Poly1305InsecureTagSize is the size of the tag.
	ChaCha20Poly1305InsecureTagSize = chacha20poly1305.Overhead

	maxPlaintextSize = maxInt - ChaCha20Poly1305InsecureNonceSize - ChaCha20Poly1305InsecureTagSize
)

// ChaCha20Poly1305InsecureNonce is an insecure implementation of the AEAD
// interface that permits the user to set the nonce.
type ChaCha20Poly1305InsecureNonce struct {
	cipher cipher.AEAD
}

// NewChaCha20Poly1305InsecureNonce returns a ChaCha20Poly1305InsecureNonce instance.
// The key argument should be a 32-bytes key.
func NewChaCha20Poly1305InsecureNonce(key []byte) (*ChaCha20Poly1305InsecureNonce, error) {
	c, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &ChaCha20Poly1305InsecureNonce{cipher: c}, nil
}

// Encrypt encrypts plaintext with nonce and associatedData.
func (ca *ChaCha20Poly1305InsecureNonce) Encrypt(dst, nonce, plaintext, associatedData []byte) ([]byte, error) {
	if len(plaintext) > maxPlaintextSize {
		return nil, fmt.Errorf("plaintext too long")
	}
	return ca.cipher.Seal(dst, nonce, plaintext, associatedData), nil
}

// Decrypt decrypts ciphertext with nonce and associatedData.
func (ca *ChaCha20Poly1305InsecureNonce) Decrypt(nonce, ciphertext, associatedData []byte) ([]byte, error) {
	if len(nonce) != ChaCha20Poly1305InsecureNonceSize {
		return nil, fmt.Errorf("invalid nonce length: got %d, want %d", len(nonce), ChaCha20Poly1305InsecureNonceSize)
	}
	if len(ciphertext) < ChaCha20Poly1305InsecureTagSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return ca.cipher.Open(nil, nonce, ciphertext, associatedData)
}
