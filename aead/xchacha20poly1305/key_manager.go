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

package xchacha20poly1305

import (
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/subtle/random"

	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	tpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	xpb "github.com/tink-crypto/tink-go/v2/proto/xchacha20_poly1305_go_proto"
)

const (
	keyVersion = 0
	typeURL    = "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key"
)

// keyManager generates [xpb.XChaCha20Poly1305Key] keys and produces
// instances of [subtle.XChaCha20Poly1305].
type keyManager struct{}

// Assert that keyManager implements the KeyManager interface.
var _ registry.KeyManager = (*keyManager)(nil)

// Primitive constructs a XChaCha20Poly1305 for the given serialized
// [xpb.XChaCha20Poly1305Key].
func (km *keyManager) Primitive(serializedKey []byte) (any, error) {
	keySerialization, err := protoserialization.NewKeySerialization(&tinkpb.KeyData{
		TypeUrl:         typeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, tinkpb.OutputPrefixType_RAW, 0)
	if err != nil {
		return nil, err
	}
	key, err := protoserialization.ParseKey(keySerialization)
	if err != nil {
		return nil, err
	}
	xChaCha20Poly1305Key, ok := key.(*Key)
	if !ok {
		return nil, fmt.Errorf("xchacha20poly1305_key_manager: invalid key type: got %T, want %T", key, (*Key)(nil))
	}
	ret, err := newAEAD(xChaCha20Poly1305Key)
	if err != nil {
		return nil, fmt.Errorf("xchacha20poly1305_key_manager: %v", err)
	}
	return ret, nil
}

// NewKey generates a new [xpb.XChaCha20Poly1305Key].
//
// It ignores serializedKeyFormat because the key size and other params are fixed.
func (km *keyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return &xpb.XChaCha20Poly1305Key{
		Version:  keyVersion,
		KeyValue: random.GetRandomBytes(chacha20poly1305.KeySize),
	}, nil
}

// NewKeyData generates a new KeyData. It ignores serializedKeyFormat because
// the key size and other params are fixed. This should be used solely by the
// key management API.
func (km *keyManager) NewKeyData(serializedKeyFormat []byte) (*tpb.KeyData, error) {
	key := &xpb.XChaCha20Poly1305Key{
		Version:  keyVersion,
		KeyValue: random.GetRandomBytes(chacha20poly1305.KeySize),
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &tpb.KeyData{
		TypeUrl:         typeURL,
		Value:           serializedKey,
		KeyMaterialType: km.KeyMaterialType(),
	}, nil
}

// DoesSupport checks whether this key manager supports the given key type.
func (km *keyManager) DoesSupport(typeURL string) bool { return km.TypeURL() == typeURL }

// TypeURL returns the type URL of keys managed by this key manager.
func (km *keyManager) TypeURL() string { return typeURL }

// KeyMaterialType returns the key material type of this key manager.
func (km *keyManager) KeyMaterialType() tpb.KeyData_KeyMaterialType {
	return tpb.KeyData_SYMMETRIC
}

// DeriveKey derives a new key from serializedKeyFormat and pseudorandomness.
//
// Unlike NewKey, DeriveKey validates serializedKeyFormat's version.
func (km *keyManager) DeriveKey(serializedKeyFormat []byte, pseudorandomness io.Reader) (proto.Message, error) {
	keyFormat := new(xpb.XChaCha20Poly1305KeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("xchacha20poly1305_key_manager: %v", err)
	}
	err := keyset.ValidateKeyVersion(keyFormat.Version, keyVersion)
	if err != nil {
		return nil, fmt.Errorf("xchacha20poly1305_key_manager: %v", err)
	}

	keyValue := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(pseudorandomness, keyValue); err != nil {
		return nil, fmt.Errorf("xchacha20poly1305_key_manager: not enough pseudorandomness given")
	}
	return &xpb.XChaCha20Poly1305Key{
		Version:  keyVersion,
		KeyValue: keyValue,
	}, nil
}

// validateKey validates the given [xpb.XChaCha20Poly1305Key].
func (km *keyManager) validateKey(key *xpb.XChaCha20Poly1305Key) error {
	err := keyset.ValidateKeyVersion(key.Version, keyVersion)
	if err != nil {
		return fmt.Errorf("xchacha20poly1305_key_manager: %v", err)
	}
	keySize := uint32(len(key.KeyValue))
	if keySize != chacha20poly1305.KeySize {
		return fmt.Errorf("xchacha20poly1305_key_manager: key size != %d", chacha20poly1305.KeySize)
	}
	return nil
}
