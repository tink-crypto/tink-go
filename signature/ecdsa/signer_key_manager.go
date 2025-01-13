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

package ecdsa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/keyset"
	subtleSignature "github.com/tink-crypto/tink-go/v2/signature/subtle"
	"github.com/tink-crypto/tink-go/v2/subtle"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	ecdsapb "github.com/tink-crypto/tink-go/v2/proto/ecdsa_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	signerKeyVersion = 0
	signerTypeURL    = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"
)

// common errors
var errInvalidSignKey = errors.New("ecdsa_signer_key_manager: invalid key")
var errInvalidSignKeyFormat = errors.New("ecdsa_signer_key_manager: invalid key format")

// signerKeyManager is an implementation of KeyManager interface.
// It generates new ECDSA private keys and produces new instances of
// [subtleSignature.ECDSASigner].
type signerKeyManager struct{}

// Primitive creates an [subtleSignature.ECDSASigner] for the given serialized
// [ecdsapb.EcdsaPrivateKey] proto.
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
		return nil, fmt.Errorf("ecdsa_signer_key_manager: invalid key type: got %T, want %T", key, (*PrivateKey)(nil))
	}
	return NewSigner(signerKey, internalapi.Token{})
}

// NewKey creates a new [ecdsapb.EcdsaPrivateKey] according to specification
// the given serialized [ecdsapb.EcdsaKeyFormat].
func (km *signerKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidSignKeyFormat
	}
	keyFormat := new(ecdsapb.EcdsaKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("ecdsa_signer_key_manager: invalid proto: %s", err)
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("ecdsa_signer_key_manager: invalid key format: %s", err)
	}
	// generate key
	params := keyFormat.GetParams()
	curve := commonpb.EllipticCurveType_name[int32(params.Curve)]
	tmpKey, err := ecdsa.GenerateKey(subtle.GetCurve(curve), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdsa_signer_key_manager: cannot generate ECDSA key: %s", err)
	}

	keyValue := tmpKey.D.Bytes()
	priv := &ecdsapb.EcdsaPrivateKey{
		Version: signerKeyVersion,
		PublicKey: &ecdsapb.EcdsaPublicKey{
			Version: signerKeyVersion,
			Params:  params,
			X:       tmpKey.X.Bytes(),
			Y:       tmpKey.Y.Bytes(),
		},
		KeyValue: keyValue,
	}
	return priv, nil
}

// NewKeyData creates a new [tinkpb.KeyData] according to specification in then
// give serialized [ecdsapb.EcdsaKeyFormat]. It should be used solely by the
// key management API.
func (km *signerKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, errInvalidSignKeyFormat
	}
	return &tinkpb.KeyData{
		TypeUrl:         signerTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

// PublicKeyData extracts the public key as [tinkpb.KeyData] from the private
// key.
func (km *signerKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(ecdsapb.EcdsaPrivateKey)
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
func (km *signerKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == signerTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *signerKeyManager) TypeURL() string { return signerTypeURL }

// validateKey validates the given [ecdsapb.EcdsaPrivateKey].
func (km *signerKeyManager) validateKey(key *ecdsapb.EcdsaPrivateKey) error {
	if err := keyset.ValidateKeyVersion(key.Version, signerKeyVersion); err != nil {
		return fmt.Errorf("invalid key version in key: %s", err)
	}
	if err := keyset.ValidateKeyVersion(key.GetPublicKey().GetVersion(), signerKeyVersion); err != nil {
		return fmt.Errorf("invalid public version in key: %s", err)
	}

	hash, curve, encoding := paramNames(key.GetPublicKey().GetParams())
	return subtleSignature.ValidateECDSAParams(hash, curve, encoding)
}

// validateKeyFormat validates the given [ecdsapb.EcdsaKeyFormat].
func (km *signerKeyManager) validateKeyFormat(format *ecdsapb.EcdsaKeyFormat) error {
	hash, curve, encoding := paramNames(format.GetParams())
	return subtleSignature.ValidateECDSAParams(hash, curve, encoding)
}
