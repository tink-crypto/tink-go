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
	"math/big"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/hybrid/internal/ecies"
	"github.com/tink-crypto/tink-go/v2/hybrid/subtle"
	"github.com/tink-crypto/tink-go/v2/keyset"
	eahpb "github.com/tink-crypto/tink-go/v2/proto/ecies_aead_hkdf_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const publicKeyVersion = 0

// publicKeyKeyManager is an implementation of KeyManager interface.
// It generates new ECIESAEADHKDFPublicKeyKey keys and produces new instances of ECIESAEADHKDFPublicKey subtle.
type publicKeyKeyManager struct{}

// Assert that publicKeyKeyManager implements the KeyManager interface.
var _ registry.KeyManager = (*publicKeyKeyManager)(nil)

// Primitive creates an ECIESAEADHKDFPublicKey subtle for the given serialized ECIESAEADHKDFPublicKey proto.
func (km *publicKeyKeyManager) Primitive(serializedKey []byte) (any, error) {
	if len(serializedKey) == 0 {
		return nil, fmt.Errorf("ecies_aead_hkdf_public_key_manager: empty key")
	}
	key := new(eahpb.EciesAeadHkdfPublicKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, fmt.Errorf("ecies_aead_hkdf_public_key_manager: %v", err)
	}
	if err := km.validateKey(key); err != nil {
		return nil, fmt.Errorf("ecies_aead_hkdf_public_key_manager: %v", err)
	}
	params := key.GetParams()
	curve, err := subtle.GetCurve(params.GetKemParams().GetCurveType().String())
	if err != nil {
		return nil, err
	}
	pub := subtle.ECPublicKey{
		Curve: curve,
		Point: subtle.ECPoint{
			X: new(big.Int).SetBytes(key.GetX()),
			Y: new(big.Int).SetBytes(key.GetY()),
		},
	}
	rDem, err := ecies.NewDEMHelper(params.GetDemParams().GetAeadDem())
	if err != nil {
		return nil, err
	}
	salt := params.GetKemParams().GetHkdfSalt()
	hash := params.GetKemParams().GetHkdfHashType().String()
	pointFormat := params.GetEcPointFormat().String()

	return subtle.NewECIESAEADHKDFHybridEncrypt(&pub, salt, hash, pointFormat, rDem)
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *publicKeyKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == publicKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *publicKeyKeyManager) TypeURL() string { return publicKeyTypeURL }

// validateKey validates the given ECDSAPrivateKey.
func (km *publicKeyKeyManager) validateKey(key *eahpb.EciesAeadHkdfPublicKey) error {
	if err := keyset.ValidateKeyVersion(key.GetVersion(), publicKeyVersion); err != nil {
		return fmt.Errorf("ecies_aead_hkdf_public_key_manager: invalid key: %s", err)
	}
	return checkECIESAEADHKDFParams(key.Params)
}

// NewKey is not implemented for public key manager.
func (km *publicKeyKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errors.New("ecies_aead_hkdf_public_key_manager: public key manager does not implement NewKey")
}

// NewKeyData is not implemented for public key manager.
func (km *publicKeyKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errors.New("ecies_aead_hkdf_public_key_manager: public key manager does not implement NewKeyData")
}
