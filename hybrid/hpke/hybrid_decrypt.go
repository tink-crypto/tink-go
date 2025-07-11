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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hpke

import (
	"bytes"
	"fmt"

	internalhpke "github.com/tink-crypto/tink-go/v2/hybrid/internal/hpke"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/tink"
)

type hybridDecrypt struct {
	rawHybridDecrypt tink.HybridDecrypt
	prefix           []byte
	variant          Variant
}

// NewHybridDecrypt creates a new instance of [tink.HybridDecrypt] from a
// [PrivateKey].
//
// This is an internal API.
func NewHybridDecrypt(privateKey *PrivateKey, _ internalapi.Token) (tink.HybridDecrypt, error) {
	serializedPrivateKey, err := protoserialization.SerializeKey(privateKey)
	if err != nil {
		return nil, err
	}
	protoPrivateKey, err := unmarshalHpkePrivateKey(serializedPrivateKey.KeyData().GetValue())
	if err != nil {
		return nil, err
	}
	rawHybridDecrypt, err := internalhpke.NewDecrypt(protoPrivateKey)
	if err != nil {
		return nil, err
	}
	return &hybridDecrypt{
		rawHybridDecrypt: rawHybridDecrypt,
		prefix:           privateKey.OutputPrefix(),
		variant:          privateKey.Parameters().(*Parameters).Variant(),
	}, nil
}

func (e *hybridDecrypt) Decrypt(ciphertext, contextInfo []byte) ([]byte, error) {
	if len(ciphertext) < len(e.prefix) {
		return nil, fmt.Errorf("ciphertext too short")
	}
	if !bytes.Equal(e.prefix, ciphertext[:len(e.prefix)]) {
		return nil, fmt.Errorf("ciphertext does not start with the expected prefix")
	}
	return e.rawHybridDecrypt.Decrypt(ciphertext[len(e.prefix):], contextInfo)
}

func hybridDecryptConstructor(k key.Key) (any, error) {
	that, ok := k.(*PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid key type, got %T, want %T", k, (*PrivateKey)(nil))
	}
	return NewHybridDecrypt(that, internalapi.Token{})
}
