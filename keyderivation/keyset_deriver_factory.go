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

package keyderivation

import (
	"errors"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveset"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/keyderivation/internal/keyderiver"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

var errNotKeysetDeriverPrimitive = errors.New("keyset_deriver_factory: not a Keyset Deriver primitive")

// New generates a new instance of the Keyset Deriver primitive.
func New(handle *keyset.Handle) (KeysetDeriver, error) {
	ps, err := keyset.Primitives[keyderiver.KeyDeriver](handle, internalapi.Token{})
	if err != nil {
		return nil, fmt.Errorf("keyset_deriver_factory: cannot obtain primitive set: %v", err)
	}
	return &wrappedKeysetDeriver{ps: ps}, nil
}

// wrappedKeysetDeriver is a Keyset Deriver implementation that uses the underlying primitive set to derive keysets.
type wrappedKeysetDeriver struct {
	ps *primitiveset.PrimitiveSet[keyderiver.KeyDeriver]
}

// Asserts that wrappedKeysetDeriver implements the KeysetDeriver interface.
var _ KeysetDeriver = (*wrappedKeysetDeriver)(nil)

func (w *wrappedKeysetDeriver) DeriveKeyset(salt []byte) (*keyset.Handle, error) {
	keys := make([]*tinkpb.Keyset_Key, 0, len(w.ps.EntriesInKeysetOrder))
	for _, e := range w.ps.EntriesInKeysetOrder {
		derivedKey, err := e.Primitive.DeriveKey(salt)
		if err != nil {
			return nil, errors.New("keyset_deriver_factory: keyset derivation failed")
		}
		keySerialization, err := protoserialization.SerializeKey(derivedKey)
		if err != nil {
			return nil, fmt.Errorf("keyset_deriver_factory: cannot get proto key from entry: %v", err)
		}
		// Set all fields, except for KeyData, to match the Entry in the keyset.
		key := &tinkpb.Keyset_Key{
			KeyData:          keySerialization.KeyData(),
			Status:           e.Status,
			KeyId:            e.KeyID,
			OutputPrefixType: e.PrefixType,
		}
		keys = append(keys, key)
	}
	ks := &tinkpb.Keyset{
		PrimaryKeyId: w.ps.Primary.KeyID,
		Key:          keys,
	}
	return keysetHandle(ks)
}
