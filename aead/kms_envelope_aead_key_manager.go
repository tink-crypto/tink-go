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

package aead

import (
	"errors"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/keyset"
	kmsepb "github.com/tink-crypto/tink-go/v2/proto/kms_envelope_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
)

const (
	kmsEnvelopeAEADKeyVersion = 0
	kmsEnvelopeAEADTypeURL    = "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey"
)

// kmsEnvelopeAEADKeyManager is an implementation of KeyManager interface.
// It generates new KMSEnvelopeAEADKey keys and produces new instances of KMSEnvelopeAEAD subtle.
type kmsEnvelopeAEADKeyManager struct{}

// Primitive creates an KMSEnvelopeAEAD subtle for the given serialized KMSEnvelopeAEADKey proto.
func (km *kmsEnvelopeAEADKeyManager) Primitive(serializedKey []byte) (any, error) {
	if len(serializedKey) == 0 {
		return nil, errors.New("kms_envelope_aead_key_manager: invalid key")
	}
	key := new(kmsepb.KmsEnvelopeAeadKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errors.New("kms_envelope_aead_key_manager: invalid key")
	}
	if err := km.validateKey(key); err != nil {
		return nil, fmt.Errorf("kms_envelope_aead_key_manager: %v", err)
	}
	uri := key.GetParams().GetKekUri()
	kmsClient, err := registry.GetKMSClient(uri)
	if err != nil {
		return nil, err
	}
	backend, err := kmsClient.GetAEAD(uri)
	if err != nil {
		return nil, errors.New("kms_envelope_aead_key_manager: invalid aead backend")
	}

	return NewKMSEnvelopeAEAD2(key.GetParams().GetDekTemplate(), backend), nil
}

// NewKey creates a new key according to specification the given serialized KMSEnvelopeAEADKeyFormat.
func (km *kmsEnvelopeAEADKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errors.New("kms_envelope_aead_key_manager: invalid key format")
	}
	keyFormat := new(kmsepb.KmsEnvelopeAeadKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, errors.New("kms_envelope_aead_key_manager: invalid key format")
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("kms_envelope_aead_key_manager: %v", err)
	}
	return &kmsepb.KmsEnvelopeAeadKey{
		Version: kmsEnvelopeAEADKeyVersion,
		Params:  keyFormat,
	}, nil
}

// NewKeyData creates a new KeyData according to specification in the given serialized
// KMSEnvelopeAEADKeyFormat.
// It should be used solely by the key management API.
func (km *kmsEnvelopeAEADKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         kmsEnvelopeAEADTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_REMOTE,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *kmsEnvelopeAEADKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == kmsEnvelopeAEADTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *kmsEnvelopeAEADKeyManager) TypeURL() string {
	return kmsEnvelopeAEADTypeURL
}

// validateKey validates the given KmsEnvelopeAeadKey.
func (km *kmsEnvelopeAEADKeyManager) validateKey(key *kmsepb.KmsEnvelopeAeadKey) error {
	if err := keyset.ValidateKeyVersion(key.Version, kmsEnvelopeAEADKeyVersion); err != nil {
		return err
	}
	if err := km.validateKeyFormat(key.GetParams()); err != nil {
		return err
	}
	return nil
}

func (km *kmsEnvelopeAEADKeyManager) validateKeyFormat(keyFormat *kmsepb.KmsEnvelopeAeadKeyFormat) error {
	dekKeyType := keyFormat.GetDekTemplate().GetTypeUrl()
	if !isSupportedKMSEnvelopeDEK(dekKeyType) {
		return fmt.Errorf("unsupported DEK key type %s. Only Tink AEAD key types are supported with KMSEnvelopeAEAD", dekKeyType)
	}
	return nil
}
