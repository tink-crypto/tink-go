// Copyright 2020 Google LLC
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

package aesgcmhkdf

import (
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
	subtleaead "github.com/tink-crypto/tink-go/v2/aead/subtle"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	ghpb "github.com/tink-crypto/tink-go/v2/proto/aes_gcm_hkdf_streaming_go_proto"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	keyVersion = 0
	typeURL    = "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey"
)

type keyManager struct{}

var _ registry.KeyManager = &keyManager{}

// Primitive creates an [subtle.NewAESGCMHKDF] for the given serialized
// [ghpb.AesGcmHkdfStreamingKey].
func (km *keyManager) Primitive(serializedKey []byte) (any, error) {
	if len(serializedKey) == 0 {
		return nil, fmt.Errorf("aes_gcm_hkdf_key_manager: invalid serialized key")
	}
	key := &ghpb.AesGcmHkdfStreamingKey{}
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, fmt.Errorf("aes_gcm_hkdf_key_manager: invalid serialized key")
	}
	if err := km.validateKey(key); err != nil {
		return nil, err
	}
	ret, err := subtle.NewAESGCMHKDF(
		key.GetKeyValue(),
		key.GetParams().GetHkdfHashType().String(),
		int(key.GetParams().GetDerivedKeySize()),
		int(key.GetParams().GetCiphertextSegmentSize()),
		// no first segment offset
		0)
	if err != nil {
		return nil, fmt.Errorf("aes_gcm_hkdf_key_manager: cannot create new primitive: %s", err)
	}
	return ret, nil
}

// NewKey creates a new key according to specification in the given serialized
//
// [AesGcmHkdfStreamingKeyFormat].
func (km *keyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, fmt.Errorf("aes_gcm_hkdf_key_manager: invalid serialized key format")
	}
	keyFormat := &ghpb.AesGcmHkdfStreamingKeyFormat{}
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("aes_gcm_hkdf_key_manager: invalid serialized key format")
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("aes_gcm_hkdf_key_manager: invalid key format: %s", err)
	}
	return &ghpb.AesGcmHkdfStreamingKey{
		Version:  keyVersion,
		KeyValue: random.GetRandomBytes(keyFormat.GetKeySize()),
		Params:   keyFormat.Params,
	}, nil
}

// NewKeyData creates a new KeyData according to specification in the given serialized
// [AesGcmHkdfStreamingKeyFormat].
//
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
		TypeUrl:         km.TypeURL(),
		Value:           serializedKey,
		KeyMaterialType: km.KeyMaterialType(),
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *keyManager) DoesSupport(typeURL string) bool { return km.TypeURL() == typeURL }

// TypeURL returns the key type of keys managed by this key manager.
func (km *keyManager) TypeURL() string { return typeURL }

// KeyMaterialType returns the key material type of this key manager.
func (km *keyManager) KeyMaterialType() tinkpb.KeyData_KeyMaterialType {
	return tinkpb.KeyData_SYMMETRIC
}

// DeriveKey derives a new key from serializedKeyFormat and pseudorandomness.
func (km *keyManager) DeriveKey(serializedKeyFormat []byte, pseudorandomness io.Reader) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, fmt.Errorf("aesgcmhkdf: invalid serialized key format")
	}
	keyFormat := &ghpb.AesGcmHkdfStreamingKeyFormat{}
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("aesgcmhkdf: invalid serialized key format")
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("aes_gcm_hkdf_key_manager: invalid key format: %v", err)
	}
	if err := keyset.ValidateKeyVersion(keyFormat.GetVersion(), keyVersion); err != nil {
		return nil, fmt.Errorf("aes_gcm_hkdf_key_manager: invalid key version: %s", err)
	}

	keyValue := make([]byte, keyFormat.GetKeySize())
	if _, err := io.ReadFull(pseudorandomness, keyValue); err != nil {
		return nil, fmt.Errorf("aes_gcm_hkdf_key_manager: not enough pseudorandomness given")
	}
	return &ghpb.AesGcmHkdfStreamingKey{
		Version:  keyVersion,
		KeyValue: keyValue,
		Params:   keyFormat.GetParams(),
	}, nil
}

// validateKey validates the given AESGCMHKDFKey.
func (km *keyManager) validateKey(key *ghpb.AesGcmHkdfStreamingKey) error {
	if err := keyset.ValidateKeyVersion(key.Version, keyVersion); err != nil {
		return fmt.Errorf("aes_gcm_hkdf_key_manager: %s", err)
	}
	keySize := uint32(len(key.GetKeyValue()))
	if err := subtleaead.ValidateAESKeySize(keySize); err != nil {
		return fmt.Errorf("aes_gcm_hkdf_key_manager: %s", err)
	}
	return km.validateParams(key.GetParams())
}

// validateKeyFormat validates the given AESGCMHKDFKeyFormat.
func (km *keyManager) validateKeyFormat(format *ghpb.AesGcmHkdfStreamingKeyFormat) error {
	if err := subtleaead.ValidateAESKeySize(format.KeySize); err != nil {
		return fmt.Errorf("aes_gcm_hkdf_key_manager: %s", err)
	}
	return km.validateParams(format.GetParams())
}

// validateKeyFormat validates the given AESGCMHKDFKeyFormat.
func (km *keyManager) validateParams(params *ghpb.AesGcmHkdfStreamingParams) error {
	if err := subtleaead.ValidateAESKeySize(params.GetDerivedKeySize()); err != nil {
		return fmt.Errorf("aes_gcm_hkdf_key_manager: %s", err)
	}
	if params.GetHkdfHashType() != commonpb.HashType_SHA1 && params.GetHkdfHashType() != commonpb.HashType_SHA256 && params.GetHkdfHashType() != commonpb.HashType_SHA512 {
		return fmt.Errorf("aes_gcm_hkdf_key_manager: unknown HKDF hash type")
	}
	if params.GetCiphertextSegmentSize() > 0x7fffffff {
		return fmt.Errorf("aes_gcm_hkdf_key_manager: CiphertextSegmentSize must be at most 2^31 - 1")
	}
	minSegmentSize := params.GetDerivedKeySize() + subtle.AESGCMHKDFNoncePrefixSizeInBytes + subtle.AESGCMHKDFTagSizeInBytes + 2
	if params.GetCiphertextSegmentSize() < minSegmentSize {
		return fmt.Errorf("aes_gcm_hkdf_key_manager: ciphertext segment_size must be at least (derivedKeySize + noncePrefixInBytes + tagSizeInBytes + 2)")
	}
	return nil
}
