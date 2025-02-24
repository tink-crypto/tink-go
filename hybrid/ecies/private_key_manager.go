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

package ecies

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/hybrid/internal/ecies"
	"github.com/tink-crypto/tink-go/v2/hybrid/subtle"
	"github.com/tink-crypto/tink-go/v2/keyset"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	eciespb "github.com/tink-crypto/tink-go/v2/proto/ecies_aead_hkdf_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const privateKeyKeyVersion = 0

// privateKeyKeyManager is an implementation of [registry.PrivateKeyManager]
// interface.
//
// It generates new [eciespb.EciesAeadHkdfPrivateKey] keys and produces new
// instances of [subtle.ECIESAEADHKDFHybridDecrypt] primitives.
type privateKeyKeyManager struct{}

var _ registry.PrivateKeyManager = (*privateKeyKeyManager)(nil)

// Primitive creates a [subtle.ECIESAEADHKDFHybridDecrypt] subtle for the given
// serialized [eciespb.ECIESAEADHKDFPrivateKey] proto.
func (km *privateKeyKeyManager) Primitive(serializedKey []byte) (any, error) {
	if len(serializedKey) == 0 {
		return nil, fmt.Errorf("ecies_aead_hkdf_private_key_manager: invalid key size")
	}
	key := new(eciespb.EciesAeadHkdfPrivateKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, fmt.Errorf("ecies_aead_hkdf_private_key_manager: %v", err)
	}
	if err := km.validateKey(key); err != nil {
		return nil, fmt.Errorf("ecies_aead_hkdf_private_key_manager: %v", err)
	}
	params := key.GetPublicKey().GetParams()
	curve, err := subtle.GetCurve(params.GetKemParams().GetCurveType().String())
	if err != nil {
		return nil, err
	}
	pvt := subtle.GetECPrivateKey(curve, key.GetKeyValue())
	rDem, err := ecies.NewDEMHelper(params.GetDemParams().GetAeadDem())
	if err != nil {
		return nil, err
	}
	salt := params.GetKemParams().GetHkdfSalt()
	hash := params.GetKemParams().GetHkdfHashType().String()
	pointFormat := params.GetEcPointFormat().String()
	return subtle.NewECIESAEADHKDFHybridDecrypt(pvt, salt, hash, pointFormat, rDem)
}

// NewKey creates a new key according to specification the given serialized
// [eciespb.EciesAeadHkdfKeyFormat].
func (km *privateKeyKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, fmt.Errorf("ecies_aead_hkdf_private_key_manager: empty key format")
	}
	keyFormat := new(eciespb.EciesAeadHkdfKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("ecies_aead_hkdf_private_key_manager: %v", err)
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("ecies_aead_hkdf_private_key_manager: %v", err)
	}
	params := keyFormat.GetParams()
	curve, err := subtle.GetCurve(params.GetKemParams().GetCurveType().String())
	if err != nil {
		return nil, err
	}
	pvt, err := subtle.GenerateECDHKeyPair(curve)
	if err != nil {
		return nil, err
	}

	return &eciespb.EciesAeadHkdfPrivateKey{
		Version:  privateKeyKeyVersion,
		KeyValue: pvt.D.Bytes(),
		PublicKey: &eciespb.EciesAeadHkdfPublicKey{
			Version: privateKeyKeyVersion,
			Params:  keyFormat.Params,
			X:       pvt.PublicKey.Point.X.Bytes(),
			Y:       pvt.PublicKey.Point.Y.Bytes(),
		},
	}, nil
}

// NewKeyData creates a new KeyData according to specification in the given serialized
// ECIESAEADHKDFPrivateKeyKeyFormat.
// It should be used solely by the key management API.
func (km *privateKeyKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         privateKeyTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

func (km *privateKeyKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(eciespb.EciesAeadHkdfPrivateKey)
	if err := proto.Unmarshal(serializedPrivKey, privKey); err != nil {
		return nil, fmt.Errorf("ecies_aead_hkdf_private_key_manager: %v", err)
	}
	if err := km.validateKey(privKey); err != nil {
		return nil, err
	}
	serializedPubKey, err := proto.Marshal(privKey.GetPublicKey())
	if err != nil {
		return nil, fmt.Errorf("ecies_aead_hkdf_private_key_manager: %v", err)
	}
	return &tinkpb.KeyData{
		TypeUrl:         publicKeyTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *privateKeyKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == privateKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *privateKeyKeyManager) TypeURL() string {
	return privateKeyTypeURL
}

// validateKey validates the given ECDSAPrivateKey.
func (km *privateKeyKeyManager) validateKey(key *eciespb.EciesAeadHkdfPrivateKey) error {
	if err := keyset.ValidateKeyVersion(key.GetVersion(), privateKeyKeyVersion); err != nil {
		return fmt.Errorf("ecies_aead_hkdf_private_key_manager: invalid key: %s", err)
	}
	if err := keyset.ValidateKeyVersion(key.GetPublicKey().GetVersion(), privateKeyKeyVersion); err != nil {
		return fmt.Errorf("ecies_aead_hkdf_private_key_manager: invalid key: %s", err)
	}
	return checkECIESAEADHKDFParams(key.GetPublicKey().GetParams())
}

// validateKeyFormat validates the given ECDSAKeyFormat.
func (km *privateKeyKeyManager) validateKeyFormat(format *eciespb.EciesAeadHkdfKeyFormat) error {
	return checkECIESAEADHKDFParams(format.Params)
}

func checkECIESAEADHKDFParams(params *eciespb.EciesAeadHkdfParams) error {
	_, err := subtle.GetCurve(params.GetKemParams().GetCurveType().String())
	if err != nil {
		return err
	}
	if params.GetKemParams().GetHkdfHashType() == commonpb.HashType_UNKNOWN_HASH {
		return errors.New("hash unsupported for HMAC")
	}

	if params.EcPointFormat == commonpb.EcPointFormat_UNKNOWN_FORMAT {
		return errors.New("unknown EC point format")
	}
	km, err := registry.GetKeyManager(params.GetDemParams().GetAeadDem().GetTypeUrl())
	if err != nil {
		return err
	}
	_, err = km.NewKeyData(params.GetDemParams().GetAeadDem().GetValue())
	if err != nil {
		return err
	}
	return nil
}
