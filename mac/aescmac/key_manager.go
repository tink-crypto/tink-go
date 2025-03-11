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

package aescmac

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac/subtle"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	cmacpb "github.com/tink-crypto/tink-go/v2/proto/aes_cmac_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	keyVersion = 0
	typeURL    = "type.googleapis.com/google.crypto.tink.AesCmacKey"
)

// keyManager generates new AES-CMAC keys and produces new instances of AES-CMAC.
type keyManager struct{}

// Primitive constructs a AES-CMAC instance for the given serialized CMACKey.
func (km *keyManager) Primitive(serializedKey []byte) (any, error) {
	if len(serializedKey) == 0 {
		return nil, fmt.Errorf("aes_cmac_key_manager: empty serialized key")
	}
	key := new(cmacpb.AesCmacKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, fmt.Errorf("aes_cmac_key_manager: %v", err)
	}
	if err := km.validateKey(key); err != nil {
		return nil, err
	}
	cmac, err := subtle.NewAESCMAC(key.KeyValue, key.GetParams().GetTagSize())
	if err != nil {
		return nil, err
	}
	return cmac, nil
}

// NewKey generates a new AesCmacKey according to specification in the given AesCmacKeyFormat.
func (km *keyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, fmt.Errorf("aes_cmac_key_manager: empty key format")
	}
	keyFormat := new(cmacpb.AesCmacKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("aes_cmac_key_manager: %v", err)
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("aes_cmac_key_manager: invalid key format: %s", err)
	}
	keyValue := random.GetRandomBytes(keyFormat.KeySize)
	return &cmacpb.AesCmacKey{
		Version:  keyVersion,
		Params:   keyFormat.Params,
		KeyValue: keyValue,
	}, nil
}

// NewKeyData generates a new KeyData according to specification in the given
// serialized AesCmacKeyFormat. This should be used solely by the key management API.
func (km *keyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("aes_cmac_key_manager: %v", err)
	}

	return &tinkpb.KeyData{
		TypeUrl:         typeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, nil
}

// DoesSupport checks whether this KeyManager supports the given key type.
func (km *keyManager) DoesSupport(typeURL string) bool { return typeURL == km.TypeURL() }

// TypeURL returns the type URL of keys managed by this KeyManager.
func (km *keyManager) TypeURL() string { return typeURL }

// validateKey validates the given AesCmacKey. It only validates the version of the
// key because other parameters will be validated in primitive construction.
func (km *keyManager) validateKey(key *cmacpb.AesCmacKey) error {
	err := keyset.ValidateKeyVersion(key.Version, keyVersion)
	if err != nil {
		return fmt.Errorf("aes_cmac_key_manager: invalid version: %s", err)
	}
	keySize := uint32(len(key.KeyValue))
	return subtle.ValidateCMACParams(keySize, key.GetParams().GetTagSize())
}

// validateKeyFormat validates the given AesCmacKeyFormat
func (km *keyManager) validateKeyFormat(format *cmacpb.AesCmacKeyFormat) error {
	return subtle.ValidateCMACParams(format.KeySize, format.GetParams().GetTagSize())
}
