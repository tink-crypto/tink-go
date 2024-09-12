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
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/signature/subtle"
	ecdsapb "github.com/tink-crypto/tink-go/v2/proto/ecdsa_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	verifierKeyVersion = 0
	verifierTypeURL    = "type.googleapis.com/google.crypto.tink.EcdsaPublicKey"
)

// common errors
var errInvalidVerifierKey = fmt.Errorf("ecdsa_verifier_key_manager: invalid key")
var errVerifierNotImplemented = fmt.Errorf("ecdsa_verifier_key_manager: not implemented")

// verifierKeyManager is an implementation of KeyManager interface.
// It doesn't support key generation.
type verifierKeyManager struct{}

// Primitive creates an [subtleSignature.ECDSAVerifier] for the given
// serialized [ecdsapb.EcdsaPublicKey] proto.
func (km *verifierKeyManager) Primitive(serializedKey []byte) (any, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidVerifierKey
	}
	key := new(ecdsapb.EcdsaPublicKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidVerifierKey
	}
	if err := km.validateKey(key); err != nil {
		return nil, err
	}
	hash, curve, encoding := paramNames(key.GetParams())
	ret, err := subtle.NewECDSAVerifier(hash, curve, encoding, key.X, key.Y)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// NewKey is not implemented.
func (km *verifierKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errVerifierNotImplemented
}

// NewKeyData is not implemented.
func (km *verifierKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errVerifierNotImplemented
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *verifierKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == verifierTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *verifierKeyManager) TypeURL() string { return verifierTypeURL }

// validateKey validates the given [ecdsapb.EcdsaPublicKey].
func (km *verifierKeyManager) validateKey(key *ecdsapb.EcdsaPublicKey) error {
	if err := keyset.ValidateKeyVersion(key.Version, verifierKeyVersion); err != nil {
		return err
	}
	hash, curve, encoding := paramNames(key.GetParams())
	return subtle.ValidateECDSAParams(hash, curve, encoding)
}
