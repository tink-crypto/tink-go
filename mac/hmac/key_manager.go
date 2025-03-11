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

package hmac

import (
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac/subtle"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	hmacpb "github.com/tink-crypto/tink-go/v2/proto/hmac_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	keyVersion = 0
	typeURL    = "type.googleapis.com/google.crypto.tink.HmacKey"
)

// keyManager generates new HMAC keys and produces new instances of HMAC.
type keyManager struct{}

// Primitive constructs a HMAC instance for the given serialized HMACKey.
func (km *keyManager) Primitive(serializedKey []byte) (any, error) {
	if len(serializedKey) == 0 {
		return nil, fmt.Errorf("hmac_key_manager: empty serialized key")
	}
	key := new(hmacpb.HmacKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, fmt.Errorf("hmac_key_manager: %v", err)
	}
	if err := km.validateKey(key); err != nil {
		return nil, err
	}
	hash := commonpb.HashType_name[int32(key.GetParams().GetHash())]
	hmac, err := subtle.NewHMAC(hash, key.KeyValue, key.GetParams().GetTagSize())
	if err != nil {
		return nil, err
	}
	return hmac, nil
}

// NewKey generates a new HMACKey according to specification in the given HMACKeyFormat.
func (km *keyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, fmt.Errorf("hmac_key_manager: empty key format")
	}
	keyFormat := new(hmacpb.HmacKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("hmac_key_manager: %v", err)
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("hmac_key_manager: invalid key format: %s", err)
	}
	keyValue := random.GetRandomBytes(keyFormat.KeySize)
	return &hmacpb.HmacKey{
		Version:  keyVersion,
		Params:   keyFormat.Params,
		KeyValue: keyValue,
	}, nil
}

// NewKeyData generates a new KeyData according to specification in the given
// serialized HMACKeyFormat. This should be used solely by the key management API.
func (km *keyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("hmac_key_manager: %v", err)
	}

	return &tinkpb.KeyData{
		TypeUrl:         typeURL,
		Value:           serializedKey,
		KeyMaterialType: km.KeyMaterialType(),
	}, nil
}

// DoesSupport checks whether this KeyManager supports the given key type.
func (km *keyManager) DoesSupport(typeURL string) bool { return typeURL == km.TypeURL() }

// TypeURL returns the type URL of keys managed by this KeyManager.
func (km *keyManager) TypeURL() string { return typeURL }

// KeyMaterialType returns the key material type of this key manager.
func (km *keyManager) KeyMaterialType() tinkpb.KeyData_KeyMaterialType {
	return tinkpb.KeyData_SYMMETRIC
}

// DeriveKey derives a new key from serializedKeyFormat and pseudorandomness.
func (km *keyManager) DeriveKey(serializedKeyFormat []byte, pseudorandomness io.Reader) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, fmt.Errorf("hmac_key_manager: empty key format")
	}
	keyFormat := new(hmacpb.HmacKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("hmac_key_manager: %v", err)
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("hmac_key_manager: invalid key format: %v", err)
	}
	if err := keyset.ValidateKeyVersion(keyFormat.GetVersion(), keyVersion); err != nil {
		return nil, fmt.Errorf("hmac_key_manager: invalid key version: %s", err)
	}

	keyValue := make([]byte, keyFormat.GetKeySize())
	if _, err := io.ReadFull(pseudorandomness, keyValue); err != nil {
		return nil, fmt.Errorf("hmac_key_manager: not enough pseudorandomness given")
	}
	return &hmacpb.HmacKey{
		Version:  keyVersion,
		Params:   keyFormat.Params,
		KeyValue: keyValue,
	}, nil
}

// validateKey validates the given HMACKey. It only validates the version of the
// key because other parameters will be validated in primitive construction.
func (km *keyManager) validateKey(key *hmacpb.HmacKey) error {
	err := keyset.ValidateKeyVersion(key.Version, keyVersion)
	if err != nil {
		return fmt.Errorf("hmac_key_manager: invalid version: %s", err)
	}
	keySize := uint32(len(key.KeyValue))
	hash := commonpb.HashType_name[int32(key.GetParams().GetHash())]
	return subtle.ValidateHMACParams(hash, keySize, key.GetParams().GetTagSize())
}

// validateKeyFormat validates the given HMACKeyFormat
func (km *keyManager) validateKeyFormat(format *hmacpb.HmacKeyFormat) error {
	hash := commonpb.HashType_name[int32(format.GetParams().GetHash())]
	return subtle.ValidateHMACParams(hash, format.KeySize, format.GetParams().GetTagSize())
}
