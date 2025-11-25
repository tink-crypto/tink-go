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
	"fmt"

	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/internal/registryconfig"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyderivation/internal/keyderiver"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

type fullPrimitiveWrapper struct {
	rawPrimitive  keyderiver.KeyDeriver
	idRequirement uint32
	prefixType    tinkpb.OutputPrefixType
}

var _ keyderiver.KeyDeriver = (*fullPrimitiveWrapper)(nil)

func (w *fullPrimitiveWrapper) DeriveKey(salt []byte) (key.Key, error) {
	key, err := w.rawPrimitive.DeriveKey(salt)
	if err != nil {
		return nil, err
	}
	keySerialization, err := protoserialization.SerializeKey(key)
	if err != nil {
		return nil, fmt.Errorf("cannot get proto key from entry: %v", err)
	}
	// Manually set the ID requirement and prefix type.
	newKeySerialization, err := protoserialization.NewKeySerialization(keySerialization.KeyData(), w.prefixType, w.idRequirement)
	if err != nil {
		return nil, fmt.Errorf("cannot create new key serialization: %v", err)
	}
	return protoserialization.ParseKey(newKeySerialization)
}

// New generates a new [keyderivation.KeysetDeriver] primitive with the
// global registry.
func New(handle *keyset.Handle) (KeysetDeriver, error) {
	return NewWithConfig(handle, &registryconfig.RegistryConfig{})
}

// NewWithConfig generates a new [keyderivation.KeysetDeriver] primitive
// with the provided [keyset.Config].
//
// NOTE: This is currently not usable in OSS because [keyset.Config]
// is not user-implementable.
func NewWithConfig(handle *keyset.Handle, config keyset.Config) (KeysetDeriver, error) {
	ps, err := keyset.Primitives[keyderiver.KeyDeriver](handle, config, internalapi.Token{})
	if err != nil {
		return nil, fmt.Errorf("keyset_deriver_factory: cannot obtain primitive set: %v", err)
	}

	var fullKeyDerivers []fullKeyDeriverWithKeyID
	for _, e := range ps.EntriesInKeysetOrder {
		if e.Primitive == nil {
			fullKeyDerivers = append(fullKeyDerivers, fullKeyDeriverWithKeyID{
				fullKeyDeriver: e.FullPrimitive,
				keyID:          e.KeyID,
			})
		} else {
			idRequirement := e.KeyID
			protoKey, err := protoserialization.SerializeKey(e.Key)
			if err != nil {
				return nil, fmt.Errorf("keyset_deriver_factory: cannot get proto key from entry: %v", err)
			}
			if protoKey.OutputPrefixType() == tinkpb.OutputPrefixType_RAW {
				idRequirement = 0
			}
			fullKeyDerivers = append(fullKeyDerivers, fullKeyDeriverWithKeyID{
				fullKeyDeriver: &fullPrimitiveWrapper{
					rawPrimitive:  e.Primitive,
					idRequirement: idRequirement,
					prefixType:    protoKey.OutputPrefixType(),
				},
				keyID: e.KeyID,
			})
		}
	}

	return &wrappedKeysetDeriver{fullKeyDerivers: fullKeyDerivers, primaryKeyID: ps.Primary.KeyID}, nil
}

type fullKeyDeriverWithKeyID struct {
	fullKeyDeriver keyderiver.KeyDeriver
	keyID          uint32
}

func (w *fullKeyDeriverWithKeyID) DeriveKey(salt []byte) (key.Key, error) {
	return w.fullKeyDeriver.DeriveKey(salt)
}

// wrappedKeysetDeriver is a Keyset Deriver implementation that uses the underlying primitive set to derive keysets.
type wrappedKeysetDeriver struct {
	fullKeyDerivers []fullKeyDeriverWithKeyID
	primaryKeyID    uint32
}

var _ KeysetDeriver = (*wrappedKeysetDeriver)(nil)

func (w *wrappedKeysetDeriver) DeriveKeyset(salt []byte) (*keyset.Handle, error) {
	km := keyset.NewManager()
	for _, e := range w.fullKeyDerivers {
		derivedKey, err := e.DeriveKey(salt)
		if err != nil {
			return nil, fmt.Errorf("keyset_deriver_factory: keyset derivation failed: %v", err)
		}
		km.AddKeyWithOpts(derivedKey, internalapi.Token{}, keyset.WithFixedID(e.keyID))
		if e.keyID == w.primaryKeyID {
			if err := km.SetPrimary(e.keyID); err != nil {
				return nil, fmt.Errorf("keyset_deriver_factory: cannot set primary key: %v", err)
			}
		}
	}
	return km.Handle()
}
