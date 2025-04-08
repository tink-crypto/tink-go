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

package hmacprf

import (
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/prf/subtle"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	hmacpb "github.com/tink-crypto/tink-go/v2/proto/hmac_prf_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	keyVersion = 0
	typeURL    = "type.googleapis.com/google.crypto.tink.HmacPrfKey"
)

// keyManager implements the [registry.KeyManager] interface. It
// generates new HMAC PRF keys and produces new instances of [prf.PRF].
type keyManager struct{}

// Primitive constructs a [prf.PRF] instance for the given serialized
// [hmacpb.HmacPrfKey].
func (km *keyManager) Primitive(serializedKey []byte) (any, error) {
	if len(serializedKey) == 0 {
		return nil, fmt.Errorf("hmac_prf_key_manager: empty serialized key")
	}
	key := new(hmacpb.HmacPrfKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, fmt.Errorf("hmac_prf_key_manager: invalid serialized key")
	}
	if err := km.validateKey(key); err != nil {
		return nil, fmt.Errorf("hmac_prf_key_manager: %v", err)
	}
	hash := commonpb.HashType_name[int32(key.GetParams().GetHash())]
	hmac, err := subtle.NewHMACPRF(hash, key.GetKeyValue())
	if err != nil {
		return nil, fmt.Errorf("hmac_prf_key_manager: %v", err)
	}
	return hmac, nil
}

// NewKey generates a new [hmacpb.HmacPrfKey] according to specification in the
// given [hmacpb.HmacPrfKeyFormat].
func (km *keyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, fmt.Errorf("hmac_prf_key_manager: empty key format")
	}
	keyFormat := new(hmacpb.HmacPrfKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("hmac_prf_key_manager: invalid key format")
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("hmac_prf_key_manager: invalid key format: %s", err)
	}
	return &hmacpb.HmacPrfKey{
		Version:  keyVersion,
		Params:   keyFormat.GetParams(),
		KeyValue: random.GetRandomBytes(keyFormat.GetKeySize()),
	}, nil
}

// NewKeyData generates a new KeyData according to specification in the given
// serialized [hmacpb.HmacPrfKeyFormat]. This should be used solely by the key
// management API.
func (km *keyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, fmt.Errorf("hmac_prf_key_manager: %v", err)
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("hmac_prf_key_manager: invalid key format")
	}

	return &tinkpb.KeyData{
		TypeUrl:         typeURL,
		Value:           serializedKey,
		KeyMaterialType: km.KeyMaterialType(),
	}, nil
}

// DoesSupport checks whether this KeyManager supports the given key type.
func (km *keyManager) DoesSupport(typeURL string) bool { return km.TypeURL() == typeURL }

// TypeURL returns the type URL of keys managed by this KeyManager.
func (km *keyManager) TypeURL() string { return typeURL }

// validateKey validates the given [hmacpb.HmacPrfKey]. It only validates the
// version of the key because other parameters will be validated in primitive
// construction.
func (km *keyManager) validateKey(key *hmacpb.HmacPrfKey) error {
	if err := keyset.ValidateKeyVersion(key.GetVersion(), keyVersion); err != nil {
		return fmt.Errorf("hmac_prf_key_manager: invalid version: %s", err)
	}
	keySize := uint32(len(key.GetKeyValue()))
	hash := commonpb.HashType_name[int32(key.GetParams().GetHash())]
	return subtle.ValidateHMACPRFParams(hash, keySize)
}

// KeyMaterialType returns the key material type of this key manager.
func (km *keyManager) KeyMaterialType() tinkpb.KeyData_KeyMaterialType {
	return tinkpb.KeyData_SYMMETRIC
}

// DeriveKey derives a new key from serializedKeyFormat and pseudorandomness.
func (km *keyManager) DeriveKey(serializedKeyFormat []byte, pseudorandomness io.Reader) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, fmt.Errorf("hmac_prf_key_manager: empty key format")
	}
	keyFormat := new(hmacpb.HmacPrfKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("hmac_prf_key_manager: invalid key format")
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("hmac_prf_key_manager: invalid key format: %v", err)
	}
	if err := keyset.ValidateKeyVersion(keyFormat.GetVersion(), keyVersion); err != nil {
		return nil, fmt.Errorf("hmac_prf_key_manager: invalid key version: %s", err)
	}

	keyValue := make([]byte, keyFormat.GetKeySize())
	if _, err := io.ReadFull(pseudorandomness, keyValue); err != nil {
		return nil, fmt.Errorf("hmac_prf_key_manager: not enough pseudorandomness given")
	}
	return &hmacpb.HmacPrfKey{
		Version:  keyVersion,
		Params:   keyFormat.GetParams(),
		KeyValue: keyValue,
	}, nil
}

// validateKeyFormat validates the given [hmacpb.HmacPrfKeyFormat].
func (km *keyManager) validateKeyFormat(format *hmacpb.HmacPrfKeyFormat) error {
	hash := commonpb.HashType_name[int32(format.GetParams().GetHash())]
	return subtle.ValidateHMACPRFParams(hash, format.GetKeySize())
}
