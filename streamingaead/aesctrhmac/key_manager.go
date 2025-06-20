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

package aesctrhmac

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	subtleaead "github.com/tink-crypto/tink-go/v2/aead/subtle"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/keyset"
	subtlemac "github.com/tink-crypto/tink-go/v2/mac/subtle"
	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	chpb "github.com/tink-crypto/tink-go/v2/proto/aes_ctr_hmac_streaming_go_proto"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	keyVersion = 0
	typeURL    = "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey"
)

type keyManager struct{}

var _ registry.KeyManager = &keyManager{}

// Primitive creates a [subtle.NewAESCTRHMAC] for the given serialized
// [chpb.AesCtrHmacStreamingKey].
func (km *keyManager) Primitive(serializedKey []byte) (any, error) {
	if len(serializedKey) == 0 {
		return nil, fmt.Errorf("aes_ctr_hmac_key_manager: invalid serialized key")
	}
	key := &chpb.AesCtrHmacStreamingKey{}
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, fmt.Errorf("aes_ctr_hmac_key_manager: invalid serialized key")
	}
	if err := km.validateKey(key); err != nil {
		return nil, err
	}
	p, err := subtle.NewAESCTRHMAC(
		key.GetKeyValue(),
		key.GetParams().GetHkdfHashType().String(),
		int(key.GetParams().GetDerivedKeySize()),
		key.GetParams().GetHmacParams().GetHash().String(),
		int(key.GetParams().GetHmacParams().GetTagSize()),
		int(key.GetParams().GetCiphertextSegmentSize()),
		// No first segment offset.
		0)
	if err != nil {
		return nil, fmt.Errorf("aes_ctr_hmac_key_manager: cannot create new primitive: %s", err)
	}
	return p, nil
}

// NewKey creates a new key according to specification in the given serialized
// [chpb.AesCtrHmacStreamingKeyFormat].
func (km *keyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, fmt.Errorf("aes_ctr_hmac_key_manager: invalid key format")
	}
	keyFormat := &chpb.AesCtrHmacStreamingKeyFormat{}
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("aes_ctr_hmac_key_manager: invalid key format")
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("%s: %s", fmt.Errorf("aes_ctr_hmac_key_manager: invalid key format"), err)
	}
	return &chpb.AesCtrHmacStreamingKey{
		Version:  keyVersion,
		KeyValue: random.GetRandomBytes(keyFormat.GetKeySize()),
		Params:   keyFormat.Params,
	}, nil
}

// NewKeyData creates a new KeyData according to specification in the given
// serialized [chpb.AesCtrHmacStreamingKeyFormat].
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

// validateKey validates the given AESCTRHMACKey.
func (km *keyManager) validateKey(key *chpb.AesCtrHmacStreamingKey) error {
	if err := keyset.ValidateKeyVersion(key.GetVersion(), keyVersion); err != nil {
		return err
	}
	keySize := uint32(len(key.GetKeyValue()))
	if err := subtleaead.ValidateAESKeySize(keySize); err != nil {
		return err
	}
	return km.validateParams(key.GetParams())
}

// validateKeyFormat validates the given AESCTRHMACKeyFormat.
func (km *keyManager) validateKeyFormat(format *chpb.AesCtrHmacStreamingKeyFormat) error {
	if err := subtleaead.ValidateAESKeySize(format.KeySize); err != nil {
		return err
	}
	return km.validateParams(format.GetParams())
}

// validateParams validates the given AESCTRHMACStreamingParams.
func (km *keyManager) validateParams(params *chpb.AesCtrHmacStreamingParams) error {
	if err := subtleaead.ValidateAESKeySize(params.GetDerivedKeySize()); err != nil {
		return err
	}
	if params.GetHkdfHashType() != commonpb.HashType_SHA1 && params.GetHkdfHashType() != commonpb.HashType_SHA256 && params.GetHkdfHashType() != commonpb.HashType_SHA512 {
		return fmt.Errorf("aes_ctr_hmac_key_manager: invalid HKDF hash type (%s)", params.GetHkdfHashType())
	}
	if params.GetHmacParams().GetHash() != commonpb.HashType_SHA1 && params.GetHmacParams().GetHash() != commonpb.HashType_SHA256 && params.GetHmacParams().GetHash() != commonpb.HashType_SHA512 {
		return fmt.Errorf("aes_ctr_hmac_key_manager: invalid tag algorithm (%s)", params.GetHmacParams().GetHash())
	}
	hmacHash := commonpb.HashType_name[int32(params.GetHmacParams().GetHash())]
	if err := subtlemac.ValidateHMACParams(hmacHash, subtle.AESCTRHMACKeySizeInBytes, params.GetHmacParams().GetTagSize()); err != nil {
		return err
	}
	minSegmentSize := params.GetDerivedKeySize() + subtle.AESCTRHMACNoncePrefixSizeInBytes + params.GetHmacParams().GetTagSize() + 2
	if params.GetCiphertextSegmentSize() < minSegmentSize {
		return fmt.Errorf("aes_ctr_hmac_key_manager: ciphertext segment size must be at least (derivedKeySize + noncePrefixInBytes + tagSizeInBytes + 2)")
	}
	if params.GetCiphertextSegmentSize() > 0x7fffffff {
		return fmt.Errorf("aes_ctr_hmac_key_manager: ciphertext segment size must be at most 2^31 - 1")
	}
	return nil
}
