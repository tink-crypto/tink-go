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

package ed25519

import (
	"crypto/ed25519"
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/keyset"
	ed25519pb "github.com/tink-crypto/tink-go/v2/proto/ed25519_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	verifierKeyVersion = 0
	verifierTypeURL    = "type.googleapis.com/google.crypto.tink.Ed25519PublicKey"
)

// verifierKeyManager is an implementation of KeyManager interface.
// It doesn't support key generation.
type verifierKeyManager struct{}

// Primitive creates a [subtle.ED25519Verifier] for the given serialized
// [ed25519pb.Ed25519PublicKey] proto.
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
		return nil, fmt.Errorf("ed25519_verifier_key_manager: invalid key type: got %T, want %T", key, (*PublicKey)(nil))
	}
	return NewVerifier(verifierKey, internalapi.Token{})
}

// NewKey is not implemented.
func (km *verifierKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, fmt.Errorf("ed25519_verifier_key_manager: not implemented")
}

// NewKeyData creates a new KeyData according to specification in  the given
// serialized ED25519KeyFormat. It should be used solely by the key management
// API.
func (km *verifierKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, fmt.Errorf("ed25519_verifier_key_manager: not implemented")
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *verifierKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == verifierTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *verifierKeyManager) TypeURL() string { return verifierTypeURL }

// validateKey validates the given [ed25519pb.Ed25519PublicKey].
func (km *verifierKeyManager) validateKey(key *ed25519pb.Ed25519PublicKey) error {
	if err := keyset.ValidateKeyVersion(key.Version, verifierKeyVersion); err != nil {
		return err
	}
	if len(key.KeyValue) != ed25519.PublicKeySize {
		return fmt.Errorf("ed25519_verifier_key_manager: invalid key length, required :%d", ed25519.PublicKeySize)
	}
	return nil
}
