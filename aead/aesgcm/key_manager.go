// Copyright 2018 Google LLC
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

package aesgcm

import (
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/aead"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	gcmpb "github.com/tink-crypto/tink-go/v2/proto/aes_gcm_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	keyVersion = 0
	typeURL    = "type.googleapis.com/google.crypto.tink.AesGcmKey"
)

// common errors
var errInvalidKey = fmt.Errorf("aes_gcm_key_manager: invalid key")
var errInvalidKeyFormat = fmt.Errorf("aes_gcm_key_manager: invalid key format")

// keyManager is an implementation of KeyManager interface.
// It generates new AESGCMKey keys and produces new instances of AESGCM subtle.
type keyManager struct{}

// Assert that keyManager implements the KeyManager interface.
var _ registry.KeyManager = (*keyManager)(nil)

// Primitive creates an AESGCM subtle for the given serialized AESGCMKey proto.
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
	aesGCMKey, ok := key.(*Key)
	if !ok {
		return nil, fmt.Errorf("xaesgcm_key_manager: invalid key type: got %T, want %T", key, (*Key)(nil))
	}
	ret, err := NewAEAD(aesGCMKey)
	if err != nil {
		return nil, fmt.Errorf("xaesgcm_key_manager: %v", err)
	}
	return ret, nil
}

// NewKey creates a new key according to specification the given serialized AESGCMKeyFormat.
func (km *keyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidKeyFormat
	}
	keyFormat := new(gcmpb.AesGcmKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, errInvalidKeyFormat
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("aes_gcm_key_manager: invalid key format: %s", err)
	}
	keyBytes := random.GetRandomBytes(keyFormat.KeySize)
	return &gcmpb.AesGcmKey{
		Version:  keyVersion,
		KeyValue: keyBytes,
	}, nil
}

// NewKeyData creates a new KeyData according to specification in the given serialized
// AESGCMKeyFormat.
// It should be used solely by the key management API.
func (km *keyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         typeURL,
		Value:           serializedKey,
		KeyMaterialType: km.KeyMaterialType(),
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *keyManager) DoesSupport(typeURL string) bool { return typeURL == km.TypeURL() }

// TypeURL returns the key type of keys managed by this key manager.
func (km *keyManager) TypeURL() string { return typeURL }

// KeyMaterialType returns the key material type of the key manager.
func (km *keyManager) KeyMaterialType() tinkpb.KeyData_KeyMaterialType {
	return tinkpb.KeyData_SYMMETRIC
}

// DeriveKey derives a new key from serializedKeyFormat and pseudorandomness.
func (km *keyManager) DeriveKey(serializedKeyFormat []byte, pseudorandomness io.Reader) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidKeyFormat
	}
	keyFormat := new(gcmpb.AesGcmKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, errInvalidKeyFormat
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("aes_gcm_key_manager: invalid key format: %s", err)
	}
	if err := keyset.ValidateKeyVersion(keyFormat.GetVersion(), keyVersion); err != nil {
		return nil, fmt.Errorf("aes_gcm_key_manager: invalid key version: %s", err)
	}

	keyBytes := make([]byte, keyFormat.GetKeySize())
	if _, err := io.ReadFull(pseudorandomness, keyBytes); err != nil {
		return nil, fmt.Errorf("aes_gcm_key_manager: not enough pseudorandomness given")
	}

	return &gcmpb.AesGcmKey{
		Version:  keyVersion,
		KeyValue: keyBytes,
	}, nil
}

// validateKey validates the given AESGCMKey.
func (km *keyManager) validateKey(key *gcmpb.AesGcmKey) error {
	if err := keyset.ValidateKeyVersion(key.Version, keyVersion); err != nil {
		return fmt.Errorf("aes_gcm_key_manager: %s", err)
	}
	keySize := uint32(len(key.GetKeyValue()))
	if err := aead.ValidateAESKeySize(keySize); err != nil {
		return fmt.Errorf("aes_gcm_key_manager: %s", err)
	}
	return nil
}

// validateKeyFormat validates the given AESGCMKeyFormat.
func (km *keyManager) validateKeyFormat(format *gcmpb.AesGcmKeyFormat) error {
	if err := aead.ValidateAESKeySize(format.KeySize); err != nil {
		return fmt.Errorf("aes_gcm_key_manager: %s", err)
	}
	return nil
}
