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

package hpke

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	internalaead "github.com/tink-crypto/tink-go/v2/internal/aead"
)

// chaCha20Poly1305AEAD is a ChaCha20-Poly1305 HPKE AEAD variant that
// implements interface aead.
type chaCha20Poly1305AEAD struct{}

var _ aead = (*chaCha20Poly1305AEAD)(nil)

func (c *chaCha20Poly1305AEAD) seal(key, nonce, plaintext, associatedData []byte) ([]byte, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("chacha20_poly1305: failed to create AEAD, error: %v", err)
	}
	if err := internalaead.CheckChaCha20Poly1305PlaintextSize(len(plaintext)); err != nil {
		return nil, err
	}
	return a.Seal(nil, nonce, plaintext, associatedData), nil
}

func (c *chaCha20Poly1305AEAD) open(key, nonce, ciphertext, associatedData []byte) ([]byte, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("chacha20_poly1305: failed to create AEAD, error: %v", err)
	}
	pt, err := a.Open(nil, nonce, ciphertext, associatedData)
	if err != nil {
		return nil, fmt.Errorf("chacha20_poly1305: %w", err)
	}
	return pt, nil
}

func (c *chaCha20Poly1305AEAD) id() AEADID { return ChaCha20Poly1305 }

func (c *chaCha20Poly1305AEAD) keyLength() int { return chacha20poly1305.KeySize }

func (c *chaCha20Poly1305AEAD) nonceLength() int { return chacha20poly1305.NonceSize }
