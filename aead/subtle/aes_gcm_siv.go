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
	internalaead "github.com/tink-crypto/tink-go/v2/internal/aead"
)

// AESGCMSIV is an implementation of AEAD interface.
type AESGCMSIV struct {
	impl *internalaead.AESGCMSIV
}

// NewAESGCMSIV returns an AESGCMSIV instance.
// The key argument should be the AES key, either 16 or 32 bytes to select
// AES-128 or AES-256.
func NewAESGCMSIV(key []byte) (*AESGCMSIV, error) {
	impl, err := internalaead.NewAESGCMSIV(key)
	if err != nil {
		return nil, err
	}
	return &AESGCMSIV{impl: impl}, nil
}

// Encrypt encrypts plaintext with associatedData.
func (a *AESGCMSIV) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	dst := make([]byte, 0, internalaead.AESGCMSIVNonceSize+internalaead.AESGCMSIVTagSize+len(plaintext))
	return a.impl.Encrypt(dst, plaintext, associatedData)
}

// Decrypt decrypts ciphertext with associatedData.
func (a *AESGCMSIV) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	return a.impl.Decrypt(ciphertext, associatedData)
}
