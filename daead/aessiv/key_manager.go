// Copyright 2019 Google LLC
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

package aessiv

import (
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/daead/subtle"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/subtle/random"

	aspb "github.com/tink-crypto/tink-go/v2/proto/aes_siv_go_proto"
	tpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	keyVersion = 0
	keyTypeURL = "type.googleapis.com/google.crypto.tink.AesSivKey"
)

// keyManager generates AES-SIV keys and produces instances of AES-SIV.
type keyManager struct{}

var _ registry.KeyManager = (*keyManager)(nil)

// Primitive constructs an AES-SIV for the given serialized [aspb.AesSivKey].
func (km *keyManager) Primitive(serializedKey []byte) (any, error) {
	if len(serializedKey) == 0 {
		return nil, errors.New("aes_siv_key_manager: invalid key")
	}
	key := new(aspb.AesSivKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, err
	}
	if err := km.validateKey(key); err != nil {
		return nil, err
	}
	ret, err := subtle.NewAESSIV(key.KeyValue)
	if err != nil {
		return nil, fmt.Errorf("aes_siv_key_manager: cannot create new primitive: %v", err)
	}
	return ret, nil
}

// NewKey generates a new [aspb.AesSivKey]. serializedKeyFormat is optional
// because there is only one valid key format.
func (km *keyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	// A nil serializedKeyFormat is acceptable. If specified, validate.
	if serializedKeyFormat != nil {
		keyFormat := new(aspb.AesSivKeyFormat)
		if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
			return nil, fmt.Errorf("aes_siv_key_manager: %v", err)
		}
		if keyFormat.KeySize != subtle.AESSIVKeySize {
			return nil, fmt.Errorf("aes_siv_key_manager: key size != %d", subtle.AESSIVKeySize)
		}
	}
	return &aspb.AesSivKey{
		Version:  keyVersion,
		KeyValue: random.GetRandomBytes(subtle.AESSIVKeySize),
	}, nil
}

// NewKeyData generates a new KeyData. serializedKeyFormat is optional because
// there is only one valid key format. This should be used solely by the key
// management API.
func (km *keyManager) NewKeyData(serializedKeyFormat []byte) (*tpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("aes_siv_key_manager: %v", err)
	}
	return &tpb.KeyData{
		TypeUrl:         keyTypeURL,
		Value:           serializedKey,
		KeyMaterialType: km.KeyMaterialType(),
	}, nil
}

// DoesSupport checks whether this key manager supports the given key type.
func (km *keyManager) DoesSupport(typeURL string) bool {
	return typeURL == keyTypeURL
}

// TypeURL returns the type URL of keys managed by this key manager.
func (km *keyManager) TypeURL() string { return keyTypeURL }

// KeyMaterialType returns the key material type of this key manager.
func (km *keyManager) KeyMaterialType() tpb.KeyData_KeyMaterialType { return tpb.KeyData_SYMMETRIC }

// DeriveKey derives a new [aspb.AesSivKey] from serializedKeyFormat and
// pseudorandomness.
//
// Unlike NewKey, DeriveKey validates serializedKeyFormat.
func (km *keyManager) DeriveKey(serializedKeyFormat []byte, pseudorandomness io.Reader) (proto.Message, error) {
	keyFormat := new(aspb.AesSivKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("aes_siv_key_manager: %v", err)
	}
	if keyFormat.GetKeySize() != subtle.AESSIVKeySize {
		return nil, fmt.Errorf("aes_siv_key_manager: key size != %d", subtle.AESSIVKeySize)
	}
	if err := keyset.ValidateKeyVersion(keyFormat.GetVersion(), keyVersion); err != nil {
		return nil, fmt.Errorf("aes_siv_key_manager: invalid key version: %s", err)
	}

	keyValue := make([]byte, subtle.AESSIVKeySize)
	if _, err := io.ReadFull(pseudorandomness, keyValue); err != nil {
		return nil, fmt.Errorf("aes_siv_key_manager: not enough pseudorandomness given")
	}
	return &aspb.AesSivKey{
		Version:  keyVersion,
		KeyValue: keyValue,
	}, nil
}

// validateKey validates the given AesSivKey.
func (km *keyManager) validateKey(key *aspb.AesSivKey) error {
	err := keyset.ValidateKeyVersion(key.Version, keyVersion)
	if err != nil {
		return fmt.Errorf("aes_siv_key_manager: %v", err)
	}
	keySize := uint32(len(key.KeyValue))
	if keySize != subtle.AESSIVKeySize {
		return fmt.Errorf("aes_siv_key_manager: key size != %d", subtle.AESSIVKeySize)
	}
	return nil
}
