// Copyright 2024 Google LLC
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

package xchacha20poly1305

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/tink-crypto/tink-go/v2/aead/subtle"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// aead is a [tink.AEAD] implementation for XChaCha20Poly1305.
//
// See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03.
type aead struct {
	rawAEAD *subtle.XChaCha20Poly1305
	prefix  []byte
	variant Variant
}

var _ tink.AEAD = (*aead)(nil)

func newAEAD(key *Key) (tink.AEAD, error) {
	rawAEAD, err := subtle.NewXChaCha20Poly1305(key.KeyBytes().Data(insecuresecretdataaccess.Token{}))
	if err != nil {
		return nil, err
	}
	return &aead{
		rawAEAD: rawAEAD,
		prefix:  key.OutputPrefix(),
		variant: key.parameters.Variant(),
	}, nil
}

// Encrypt encrypts plaintext with associatedData.
func (ca *aead) Encrypt(plaintext []byte, associatedData []byte) ([]byte, error) {
	ciphertext, err := ca.rawAEAD.Encrypt(plaintext, associatedData)
	if err != nil {
		return nil, err
	}
	return slices.Concat(ca.prefix, ciphertext), nil
}

// Decrypt decrypts ciphertext with associatedData.
func (ca *aead) Decrypt(ciphertext []byte, associatedData []byte) ([]byte, error) {
	if !bytes.HasPrefix(ciphertext, ca.prefix) {
		return nil, fmt.Errorf("ciphertext has invalid prefix")
	}
	toDecrypt := ciphertext[len(ca.prefix):]
	plaintext, err := ca.rawAEAD.Decrypt(toDecrypt, associatedData)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
