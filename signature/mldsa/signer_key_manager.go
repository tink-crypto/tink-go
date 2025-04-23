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
	"errors"
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
	signerKeyVersion = 0
	signerTypeURL    = "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey"
)

// common errors
var errInvalidSignKey = errors.New("invalid key")
var errInvalidSignKeyFormat = errors.New("invalid key format")

// signerKeyManager is an implementation of KeyManager interface.
// It generates new [mldsapb.MlDsaPrivateKey] and produces new instances of
// [tink.MlDsaSigner].
type signerKeyManager struct{}

func generateNewKeyForProtoInstance(instance mldsapb.MlDsaInstance) (*mldsa.PublicKey, *mldsa.SecretKey, error) {
	switch instance {
	case mldsapb.MlDsaInstance_ML_DSA_65:
		pub, priv := mldsa.MLDSA65.KeyGen()
		return pub, priv, nil
	default:
		return nil, nil, fmt.Errorf("unsupported instance: %s", instance)
	}
}

// Primitive creates a [tink.Signer] instance for the given serialized
// [mldsapb.MlDsaPrivateKey] proto.
func (km *signerKeyManager) Primitive(serializedKey []byte) (any, error) {
	keySerialization, err := protoserialization.NewKeySerialization(&tinkpb.KeyData{
		TypeUrl:         signerTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, tinkpb.OutputPrefixType_RAW, 0)
	if err != nil {
		return nil, err
	}
	key, err := protoserialization.ParseKey(keySerialization)
	if err != nil {
		return nil, err
	}
	signerKey, ok := key.(*PrivateKey)
	if !ok {
		return nil, fmt.Errorf("mldsa_signer_key_manager: invalid key type: got %T, want %T", key, (*PrivateKey)(nil))
	}
	return NewSigner(signerKey, internalapi.Token{})
}

// NewKey is deprecated, use NewKeyData instead.
func (km *signerKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, fmt.Errorf("NewKey is deprecated, use NewKeyData instead")
}

// NewKeyData creates a new KeyData according to specification in the given
// serialized [mldsapb.MlDsaKeyFormat]. It should be used solely by the key
// management API.
func (km *signerKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidSignKeyFormat
	}
	keyFormat := new(mldsapb.MlDsaKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, errInvalidSignKeyFormat
	}
	pub, priv, err := generateNewKeyForProtoInstance(keyFormat.GetParams().GetMlDsaInstance())
	if err != nil {
		return nil, fmt.Errorf("cannot generate ML-DSA key: %s", err)
	}
	seed := priv.Seed()
	key := &mldsapb.MlDsaPrivateKey{
		Version:  signerKeyVersion,
		KeyValue: seed[:],
		PublicKey: &mldsapb.MlDsaPublicKey{
			Params: &mldsapb.MlDsaParams{
				MlDsaInstance: keyFormat.GetParams().GetMlDsaInstance(),
			},
			Version:  verifierKeyVersion,
			KeyValue: pub.Encode(),
		},
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, errInvalidSignKeyFormat
	}
	return &tinkpb.KeyData{
		TypeUrl:         signerTypeURL,
		Value:           serializedKey,
		KeyMaterialType: km.KeyMaterialType(),
	}, nil
}

// PublicKeyData extracts the public key data from the private key.
func (km *signerKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(mldsapb.MlDsaPrivateKey)
	if err := proto.Unmarshal(serializedPrivKey, privKey); err != nil {
		return nil, errInvalidSignKey
	}
	if err := km.validateKey(privKey); err != nil {
		return nil, err
	}
	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		return nil, errInvalidSignKey
	}
	return &tinkpb.KeyData{
		TypeUrl:         verifierTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *signerKeyManager) DoesSupport(typeURL string) bool { return typeURL == signerTypeURL }

// TypeURL returns the key type of keys managed by this key manager.
func (km *signerKeyManager) TypeURL() string { return signerTypeURL }

// KeyMaterialType returns the key material type of this key manager.
func (km *signerKeyManager) KeyMaterialType() tinkpb.KeyData_KeyMaterialType {
	return tinkpb.KeyData_ASYMMETRIC_PRIVATE
}

// validateKey validates the given [mldsapb.MlDsaPrivateKey].
func (km *signerKeyManager) validateKey(key *mldsapb.MlDsaPrivateKey) error {
	if err := keyset.ValidateKeyVersion(key.Version, signerKeyVersion); err != nil {
		return fmt.Errorf("mldsa_signer_key_manager: invalid key: %s", err)
	}
	if len(key.KeyValue) != mldsa.SecretKeySeedSize {
		return fmt.Errorf("mldsa_signer_key_manager: invalid key length, got %d", len(key.KeyValue))
	}
	if err := checkPublicKeyLengthForProtoInstance(len(key.PublicKey.GetKeyValue()), key.PublicKey.Params.GetMlDsaInstance()); err != nil {
		return fmt.Errorf("mldsa_signer_key_manager: invalid key: %s", err)
	}
	return nil
}
