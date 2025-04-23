// Copyright 2025 Google LLC
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

package mldsa

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/internal/signature/mldsa"
	"github.com/tink-crypto/tink-go/v2/keyset"
	mldsapb "github.com/tink-crypto/tink-go/v2/proto/ml_dsa_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	verifierKeyVersion = 0
	verifierTypeURL    = "type.googleapis.com/google.crypto.tink.MlDsaPublicKey"
)

// verifierKeyManager is an implementation of KeyManager interface.
// It doesn't support key generation.
type verifierKeyManager struct{}

// Primitive creates a [tink.MlDsaVerifier] for the given serialized
// [mldsapb.MlDsaPublicKey] proto.
func (km *verifierKeyManager) Primitive(serializedKey []byte) (any, error) {
	keySerialization, err := protoserialization.NewKeySerialization(&tinkpb.KeyData{
		TypeUrl:         verifierTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, tinkpb.OutputPrefixType_RAW, 0)
	if err != nil {
		return nil, err
	}
	key, err := protoserialization.ParseKey(keySerialization)
	if err != nil {
		return nil, err
	}
	verifierKey, ok := key.(*PublicKey)
	if !ok {
		return nil, fmt.Errorf("mldsa_verifier_key_manager: invalid key type: got %T, want %T", key, (*PublicKey)(nil))
	}
	return NewVerifier(verifierKey, internalapi.Token{})
}

// NewKey is not implemented.
func (km *verifierKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, fmt.Errorf("mldsa_verifier_key_manager: not implemented")
}

// NewKeyData creates a new KeyData according to specification in  the given
// serialized MLDSAKeyFormat. It should be used solely by the key management
// API.
func (km *verifierKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, fmt.Errorf("mldsa_verifier_key_manager: not implemented")
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *verifierKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == verifierTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *verifierKeyManager) TypeURL() string { return verifierTypeURL }

func checkPublicKeyLengthForProtoInstance(length int, instance mldsapb.MlDsaInstance) error {
	switch instance {
	case mldsapb.MlDsaInstance_ML_DSA_65:
		if length != mldsa.MLDSA65.PublicKeyLength() {
			return fmt.Errorf("public key length must be %d bytes", mldsa.MLDSA65.PublicKeyLength())
		}
	default:
		return fmt.Errorf("invalid instance: %v", instance)
	}
	return nil
}

// validateKey validates the given [mldsapb.MlDsaPublicKey].
func (km *verifierKeyManager) validateKey(key *mldsapb.MlDsaPublicKey) error {
	if err := keyset.ValidateKeyVersion(key.Version, verifierKeyVersion); err != nil {
		return fmt.Errorf("mldsa_verifier_key_manager: invalid key: %s", err)
	}
	if err := checkPublicKeyLengthForProtoInstance(len(key.KeyValue), key.Params.GetMlDsaInstance()); err != nil {
		return fmt.Errorf("mldsa_verifier_key_manager: invalid key: %s", err)
	}
	return nil
}
