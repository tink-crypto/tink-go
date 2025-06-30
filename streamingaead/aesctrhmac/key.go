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

package aesctrhmac

import (
	"fmt"

	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

// Key represents an AES-CTR-HMAC Streaming AEAD key.
type Key struct {
	parameters *Parameters
	keyBytes   secretdata.Bytes
}

// This ensures that the Key type implements the [key.Key] interface.
var _ key.Key = (*Key)(nil)

// NewKey creates a new AES-CTR-HMAC Streaming AEAD key.
func NewKey(parameters *Parameters, keyBytes secretdata.Bytes) (*Key, error) {
	if parameters == nil {
		return nil, fmt.Errorf("aesctrhmac.NewKey: Parameters must not be nil")
	}
	if keyBytes.Len() != parameters.KeySizeInBytes() {
		return nil, fmt.Errorf("aesctrhmac.NewKey: key has size %d, but must have size %d", keyBytes.Len(), parameters.KeySizeInBytes())
	}
	return &Key{
		parameters: parameters,
		keyBytes:   keyBytes,
	}, nil
}

// Parameters returns the parameters of the key.
func (k *Key) Parameters() key.Parameters { return k.parameters }

// KeyBytes returns the initial key material.
func (k *Key) KeyBytes() secretdata.Bytes { return k.keyBytes }

// IDRequirement always returns (0, false) for this key type.
func (k *Key) IDRequirement() (uint32, bool) { return 0, false }

// Equal returns true if k and other are equal.
func (k *Key) Equal(other key.Key) bool {
	that, ok := other.(*Key)
	return ok && k.parameters.Equal(that.parameters) && k.keyBytes.Equal(that.keyBytes)
}
