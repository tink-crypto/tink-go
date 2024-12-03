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

package aesgcmsiv

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/aead/subtle"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	gcmsivpb "github.com/tink-crypto/tink-go/v2/proto/aes_gcm_siv_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

// aesGCMSIVKeyManager implements [registry.KeyManager] for AES-GCM-SIV.
//
// It generates new AESGCMSIVKey keys and can create [tink.AEAD] primitives
// that implement AES-GCM-SIV.
type aesGCMSIVKeyManager struct{}

var _ registry.KeyManager = (*aesGCMSIVKeyManager)(nil)

// Primitive creates an [tink.AEAD] primitive from a serialized
// [gcmsivpb.AesGcmSivKey].
func (km *aesGCMSIVKeyManager) Primitive(serializedKey []byte) (any, error) {
	if len(serializedKey) == 0 {
		return nil, fmt.Errorf("aes_gcm_siv_key_manager: invalid key")
	}
	key := new(gcmsivpb.AesGcmSivKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, fmt.Errorf("aes_gcm_siv_key_manager: invalid key")
	}
	if err := km.validateKey(key); err != nil {
		return nil, err
	}
	ret, err := subtle.NewAESGCMSIV(key.KeyValue)
	if err != nil {
		return nil, fmt.Errorf("aes_gcm_siv_key_manager: cannot create new primitive: %s", err)
	}
	return ret, nil
}

// NewKey creates a new [gcmsivpb.AesGcmSivKey] from the given serialized
// [gcmsivpb.AesGcmSivKeyFormat].
func (km *aesGCMSIVKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, fmt.Errorf("aes_gcm_siv_key_manager: invalid key format")
	}
	keyFormat := new(gcmsivpb.AesGcmSivKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("aes_gcm_siv_key_manager: invalid key format")
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("aes_gcm_siv_key_manager: invalid key format: %s", err)
	}
	keyValue := random.GetRandomBytes(keyFormat.KeySize)
	return &gcmsivpb.AesGcmSivKey{
		Version:  0,
		KeyValue: keyValue,
	}, nil
}

// NewKeyData creates a new [tinkpb.KeyData] from the given serialized
// [gcmsivpb.AesGcmSivKeyFormat].
//
// It should be used solely by the key management API.
func (km *aesGCMSIVKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
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
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *aesGCMSIVKeyManager) DoesSupport(typeURL string) bool { return km.TypeURL() == typeURL }

// TypeURL returns the key type of keys managed by this key manager.
func (km *aesGCMSIVKeyManager) TypeURL() string { return typeURL }

func (km *aesGCMSIVKeyManager) validateKey(key *gcmsivpb.AesGcmSivKey) error {
	err := keyset.ValidateKeyVersion(key.Version, 0)
	if err != nil {
		return fmt.Errorf("aes_gcm_siv_key_manager: %s", err)
	}
	keySize := uint32(len(key.KeyValue))
	if err := subtle.ValidateAESKeySize(keySize); err != nil {
		return fmt.Errorf("aes_gcm_siv_key_manager: %s", err)
	}
	return nil
}

func (km *aesGCMSIVKeyManager) validateKeyFormat(format *gcmsivpb.AesGcmSivKeyFormat) error {
	if err := subtle.ValidateAESKeySize(format.KeySize); err != nil {
		return fmt.Errorf("aes_gcm_siv_key_manager: %s", err)
	}
	return nil
}

type config interface {
	RegisterKeyManager(keyTypeURL string, km registry.KeyManager, t internalapi.Token) error
}

// RegisterKeyManager accepts a config object and registers an
// instance of an AES-GCM-SIV AEAD KeyManager to the provided config.
//
// It is *NOT* part of the public API.
func RegisterKeyManager(c config, t internalapi.Token) error {
	return c.RegisterKeyManager(typeURL, new(aesGCMSIVKeyManager), t)
}
