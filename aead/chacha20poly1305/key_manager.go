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

package chacha20poly1305

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/subtle/random"

	cppb "github.com/tink-crypto/tink-go/v2/proto/chacha20_poly1305_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	keyVersion = 0
	typeURL    = "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key"
)

// Common errors.
var (
	errInvalidKey       = fmt.Errorf("chacha20poly1305_key_manager: invalid key")
	errInvalidKeyFormat = fmt.Errorf("chacha20poly1305_key_manager: invalid key format")
)

// keyManager is an implementation of KeyManager interface.
// It generates new ChaCha20Poly1305Key keys and produces new instances of ChaCha20Poly1305 subtle.
type keyManager struct{}

// Primitive creates an ChaCha20Poly1305 subtle for the given serialized ChaCha20Poly1305Key proto.
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
	chaCha20Poly1305Key, ok := key.(*Key)
	if !ok {
		return nil, fmt.Errorf("chacha20poly1305_key_manager: invalid key type: got %T, want %T", key, (*Key)(nil))
	}
	ret, err := newAEAD(chaCha20Poly1305Key)
	if err != nil {
		return nil, fmt.Errorf("chacha20poly1305_key_manager: %v", err)
	}
	return ret, nil
}

// NewKey creates a new key, ignoring the specification in the given serialized key format
// because the key size and other params are fixed.
func (km *keyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return km.newChaCha20Poly1305Key(), nil
}

// NewKeyData creates a new KeyData ignoring the specification in the given serialized key format
// because the key size and other params are fixed.
// It should be used solely by the key management API.
func (km *keyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key := km.newChaCha20Poly1305Key()
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         typeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *keyManager) DoesSupport(typeURL string) bool { return km.TypeURL() == typeURL }

// TypeURL returns the key type of keys managed by this key manager.
func (km *keyManager) TypeURL() string { return typeURL }

func (km *keyManager) newChaCha20Poly1305Key() *cppb.ChaCha20Poly1305Key {
	keyValue := random.GetRandomBytes(chacha20poly1305.KeySize)
	return &cppb.ChaCha20Poly1305Key{
		Version:  keyVersion,
		KeyValue: keyValue,
	}
}

// validateKey validates the given ChaCha20Poly1305Key.
func (km *keyManager) validateKey(key *cppb.ChaCha20Poly1305Key) error {
	err := keyset.ValidateKeyVersion(key.Version, keyVersion)
	if err != nil {
		return fmt.Errorf("chacha20poly1305_key_manager: %s", err)
	}
	keySize := uint32(len(key.KeyValue))
	if keySize != chacha20poly1305.KeySize {
		return fmt.Errorf("chacha20poly1305_key_manager: keySize != %d", chacha20poly1305.KeySize)
	}
	return nil
}
