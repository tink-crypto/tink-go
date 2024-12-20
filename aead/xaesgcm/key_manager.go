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

package xaesgcm

import (
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/subtle/random"

	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	xaesgcmpb "github.com/tink-crypto/tink-go/v2/proto/x_aes_gcm_go_proto"
)

const (
	keyVersion = 0
	typeURL    = "type.googleapis.com/google.crypto.tink.XAesGcmKey"
)

// keyManager generates [xaesgcmpb.XAesGcmKey] keys and produces
// instances of [tink.AEAD] that implement X-AES-GCM.
type keyManager struct{}

// Assert that keyManager implements the KeyManager interface.
var _ registry.KeyManager = (*keyManager)(nil)

// Primitive constructs a [tink.AEAD] for the given serialized
// [xaesgcmpb.XAesGcmKey].
func (km *keyManager) Primitive(serializedKey []byte) (any, error) {
	keySerialization, err := protoserialization.NewKeySerialization(&tinkpb.KeyData{
		TypeUrl:         typeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, tinkpb.OutputPrefixType_RAW, 0)
	if err != nil {
		return nil, err
	}
	key, err := protoserialization.ParseKey(keySerialization)
	if err != nil {
		return nil, err
	}
	xAESGCMKey, ok := key.(*Key)
	if !ok {
		return nil, fmt.Errorf("invalid key type: got %T, want *xaesgcm.Key", key)
	}
	ret, err := NewAEAD(xAESGCMKey, internalapi.Token{})
	if err != nil {
		return nil, fmt.Errorf("xaesgcm_key_manager: cannot create new primitive: %v", err)
	}
	return ret, nil
}

// NewKey generates a new [xaesgcmpb.XAesGcmKey].
func (km *keyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, fmt.Errorf("xaesgcm_key_manager: empty key format")
	}
	keyFormat := new(xaesgcmpb.XAesGcmKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("xaesgcm_key_manager: %v", err)
	}
	if err := validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("xaesgcm_key_manager: %v", err)
	}
	return &xaesgcmpb.XAesGcmKey{
		Version:  keyVersion,
		KeyValue: random.GetRandomBytes(32),
		Params: &xaesgcmpb.XAesGcmParams{
			SaltSize: keyFormat.GetParams().GetSaltSize(),
		},
	}, nil
}

// NewKeyData generates a new KeyData. This should be used solely by the
// key management API.
func (km *keyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, fmt.Errorf("xaesgcm_key_manager: empty key format")
	}
	keyFormat := new(xaesgcmpb.XAesGcmKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("xaesgcm_key_manager: %v", err)
	}
	if err := validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("xaesgcm_key_manager: %v", err)
	}
	key := &xaesgcmpb.XAesGcmKey{
		Version:  keyVersion,
		KeyValue: random.GetRandomBytes(32),
		Params: &xaesgcmpb.XAesGcmParams{
			SaltSize: keyFormat.GetParams().GetSaltSize(),
		},
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("xaesgcm_key_manager: %v", err)
	}
	return &tinkpb.KeyData{
		TypeUrl:         typeURL,
		Value:           serializedKey,
		KeyMaterialType: km.KeyMaterialType(),
	}, nil
}

// DoesSupport checks whether this key manager supports the given key type.
func (km *keyManager) DoesSupport(typeURL string) bool { return km.TypeURL() == typeURL }

// TypeURL returns the type URL of keys managed by this key manager.
func (km *keyManager) TypeURL() string { return typeURL }

// KeyMaterialType returns the key material type of this key manager.
func (km *keyManager) KeyMaterialType() tinkpb.KeyData_KeyMaterialType {
	return tinkpb.KeyData_SYMMETRIC
}

// DeriveKey derives a new key from serializedKeyFormat and pseudorandomness.
//
// Unlike NewKey, DeriveKey validates serializedKeyFormat's version.
func (km *keyManager) DeriveKey(serializedKeyFormat []byte, pseudorandomness io.Reader) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, fmt.Errorf("xaesgcm_key_manager: empty key format")
	}
	keyFormat := new(xaesgcmpb.XAesGcmKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("xaesgcm_key_manager: %v", err)
	}
	err := keyset.ValidateKeyVersion(keyFormat.Version, keyVersion)
	if err != nil {
		return nil, fmt.Errorf("xaesgcm_key_manager: %v", err)
	}

	keyValue := make([]byte, 32)
	if _, err := io.ReadFull(pseudorandomness, keyValue); err != nil {
		return nil, fmt.Errorf("xaesgcm_key_manager: not enough pseudorandomness given")
	}
	return &xaesgcmpb.XAesGcmKey{
		Version:  keyVersion,
		KeyValue: keyValue,
		Params: &xaesgcmpb.XAesGcmParams{
			SaltSize: keyFormat.GetParams().GetSaltSize(),
		},
	}, nil
}

func validateKeyFormat(format *xaesgcmpb.XAesGcmKeyFormat) error {
	if err := keyset.ValidateKeyVersion(format.Version, keyVersion); err != nil {
		return fmt.Errorf("xaesgcm_key_manager: %v", err)
	}
	saltSize := format.GetParams().GetSaltSize()
	if saltSize < 8 || saltSize > 12 {
		return fmt.Errorf("xaesgcm_key_manager: salt size = %d, want in [8, 12]", saltSize)
	}
	return nil
}
