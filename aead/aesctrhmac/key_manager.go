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

package aesctrhmac

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/aead/subtle"
	"github.com/tink-crypto/tink-go/v2/keyset"
	subtleMac "github.com/tink-crypto/tink-go/v2/mac/subtle"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	ctrpb "github.com/tink-crypto/tink-go/v2/proto/aes_ctr_go_proto"
	aeadpb "github.com/tink-crypto/tink-go/v2/proto/aes_ctr_hmac_aead_go_proto"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	hmacpb "github.com/tink-crypto/tink-go/v2/proto/hmac_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	keyVersion            = 0
	typeURL               = "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey"
	minHMACKeySizeInBytes = 16
	minTagSizeInBytes     = 10
)

// keyManager generates [subtle.NewEncryptThenAuthenticate] primitives and
// [aeadpb.AesCtrHmacAeadKey] keys
type keyManager struct{}

// Primitive creates a [subtle.NewEncryptThenAuthenticate] primitive for the given
// serialized [aeadpb.AesCtrHmacAeadKey].
func (km *keyManager) Primitive(serializedKey []byte) (any, error) {
	key := new(aeadpb.AesCtrHmacAeadKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, fmt.Errorf("aes_ctr_hmac_aead_key_manager: invalid key")
	}
	if err := km.validateKey(key); err != nil {
		return nil, err
	}

	ctr, err := subtle.NewAESCTR(key.GetAesCtrKey().GetKeyValue(), int(key.GetAesCtrKey().GetParams().GetIvSize()))
	if err != nil {
		return nil, fmt.Errorf("aes_ctr_hmac_aead_key_manager: cannot create new primitive: %v", err)
	}

	hmacKey := key.GetHmacKey()
	hmac, err := subtleMac.NewHMAC(hmacKey.GetParams().GetHash().String(), hmacKey.GetKeyValue(), hmacKey.GetParams().GetTagSize())
	if err != nil {
		return nil, fmt.Errorf("aes_ctr_hmac_aead_key_manager: cannot create mac primitive, error: %v", err)
	}

	aead, err := subtle.NewEncryptThenAuthenticate(ctr, hmac, int(hmacKey.GetParams().GetTagSize()))
	if err != nil {
		return nil, fmt.Errorf("aes_ctr_hmac_aead_key_manager: cannot create encrypt then authenticate primitive, error: %v", err)
	}
	return aead, nil
}

// NewKey creates a new key according to the given serialized
// [aeadpb.AesCtrHmacAeadKeyFormat].
func (km *keyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	keyFormat := new(aeadpb.AesCtrHmacAeadKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("aes_ctr_hmac_aead_key_manager: invalid key format: %v", err)
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("aes_ctr_hmac_aead_key_manager: invalid key format: %v", err)
	}
	return &aeadpb.AesCtrHmacAeadKey{
		Version: keyVersion,
		AesCtrKey: &ctrpb.AesCtrKey{
			Version:  keyVersion,
			KeyValue: random.GetRandomBytes(keyFormat.GetAesCtrKeyFormat().GetKeySize()),
			Params:   keyFormat.GetAesCtrKeyFormat().GetParams(),
		},
		HmacKey: &hmacpb.HmacKey{
			Version:  keyVersion,
			KeyValue: random.GetRandomBytes(keyFormat.GetHmacKeyFormat().GetKeySize()),
			Params:   keyFormat.GetHmacKeyFormat().GetParams(),
		},
	}, nil
}

// NewKeyData creates a new KeyData according to specification in the given serialized
// [aeadpb.AesCtrHmacAeadKeyFormat].
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
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *keyManager) DoesSupport(typeURL string) bool { return km.TypeURL() == typeURL }

// TypeURL returns the key type of keys managed by this key manager.
func (km *keyManager) TypeURL() string { return typeURL }

// validateKey validates the given [aeadpb.AesCtrHmacAeadKey] proto.
func (km *keyManager) validateKey(key *aeadpb.AesCtrHmacAeadKey) error {
	if err := keyset.ValidateKeyVersion(key.GetVersion(), keyVersion); err != nil {
		return fmt.Errorf("aes_ctr_hmac_aead_key_manager: %v", err)
	}
	if err := keyset.ValidateKeyVersion(key.GetAesCtrKey().GetVersion(), keyVersion); err != nil {
		return fmt.Errorf("aes_ctr_hmac_aead_key_manager: %v", err)
	}
	if err := keyset.ValidateKeyVersion(key.GetHmacKey().GetVersion(), keyVersion); err != nil {
		return fmt.Errorf("aes_ctr_hmac_aead_key_manager: %v", err)
	}
	// Validate AesCtrKey.
	keySize := uint32(len(key.GetAesCtrKey().GetKeyValue()))
	if err := subtle.ValidateAESKeySize(keySize); err != nil {
		return fmt.Errorf("aes_ctr_hmac_aead_key_manager: %v", err)
	}
	params := key.GetAesCtrKey().GetParams()
	if params.GetIvSize() < subtle.AESCTRMinIVSize || params.GetIvSize() > 16 {
		return errors.New("aes_ctr_hmac_aead_key_manager: invalid AesCtrHmacAeadKey: IV size out of range")
	}
	return nil
}

// validateKeyFormat validates the given [aeadpb.AesCtrHmacAeadKeyFormat]
// proto.
func (km *keyManager) validateKeyFormat(format *aeadpb.AesCtrHmacAeadKeyFormat) error {
	// Validate AesCtrKeyFormat.
	if err := subtle.ValidateAESKeySize(format.GetAesCtrKeyFormat().GetKeySize()); err != nil {
		return fmt.Errorf("aes_ctr_hmac_aead_key_manager: %s", err)
	}
	if format.GetAesCtrKeyFormat().GetParams().GetIvSize() < subtle.AESCTRMinIVSize || format.GetAesCtrKeyFormat().GetParams().GetIvSize() > 16 {
		return errors.New("aes_ctr_hmac_aead_key_manager: invalid AesCtrHmacAeadKeyFormat: IV size out of range")
	}

	// Validate HmacKeyFormat.
	hmacKeyFormat := format.GetHmacKeyFormat()
	if hmacKeyFormat.GetKeySize() < minHMACKeySizeInBytes {
		return errors.New("aes_ctr_hmac_aead_key_manager: HMAC KeySize is too small")
	}
	if hmacKeyFormat.GetParams().GetTagSize() < minTagSizeInBytes {
		return fmt.Errorf("aes_ctr_hmac_aead_key_manager: invalid HmacParams: TagSize %d is too small", hmacKeyFormat.GetParams().GetTagSize())
	}

	maxTagSizes := map[commonpb.HashType]uint32{
		commonpb.HashType_SHA1:   20,
		commonpb.HashType_SHA224: 28,
		commonpb.HashType_SHA256: 32,
		commonpb.HashType_SHA384: 48,
		commonpb.HashType_SHA512: 64,
	}

	maxTagSize, ok := maxTagSizes[hmacKeyFormat.GetParams().GetHash()]
	if !ok {
		return fmt.Errorf("aes_ctr_hmac_aead_key_manager: invalid HmacParams: HashType %q not supported",
			hmacKeyFormat.GetParams().GetHash())
	}
	if hmacKeyFormat.GetParams().GetTagSize() > maxTagSize {
		return fmt.Errorf("aes_ctr_hmac_aead_key_manager: invalid HmacParams: tagSize %d is too big for HashType %q",
			hmacKeyFormat.GetParams().GetTagSize(), hmacKeyFormat.GetParams().GetHash())
	}

	return nil
}
