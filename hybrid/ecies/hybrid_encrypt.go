// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or rawHybridEncryptied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ecies

import (
	"fmt"
	"slices"

	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/tink"
)

type hybridEncrypt struct {
	rawHybridEncrypt tink.HybridEncrypt
	prefix           []byte
	variant          Variant
}

// NewHybridEncrypt creates a new instance of [tink.HybridEncrypt] from a
// [PublicKey].
//
// This is an internal API.
func NewHybridEncrypt(publicKey *PublicKey, _ internalapi.Token) (tink.HybridEncrypt, error) {
	serializedPublicKey, err := protoserialization.SerializeKey(publicKey)
	if err != nil {
		return nil, err
	}
	rawHybridEncrypt, err := (&publicKeyKeyManager{}).Primitive(serializedPublicKey.KeyData().GetValue())
	if err != nil {
		return nil, err
	}
	return &hybridEncrypt{
		rawHybridEncrypt: rawHybridEncrypt.(tink.HybridEncrypt),
		prefix:           publicKey.OutputPrefix(),
		variant:          publicKey.Parameters().(*Parameters).Variant(),
	}, nil
}

func (e *hybridEncrypt) Encrypt(plaintext, contextInfo []byte) ([]byte, error) {
	rawCiphertext, err := e.rawHybridEncrypt.Encrypt(plaintext, contextInfo)
	if err != nil {
		return nil, err
	}
	return slices.Concat(e.prefix, rawCiphertext), nil
}

func hybridEncryptConstructor(k key.Key) (any, error) {
	that, ok := k.(*PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid key type, got %T, want %T", k, (*PublicKey)(nil))
	}
	return NewHybridEncrypt(that, internalapi.Token{})
}
