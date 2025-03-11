// Copyright 2022 Google LLC
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

package hpke

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/hybrid/internal/hpke"
	"github.com/tink-crypto/tink-go/v2/keyset"
	hpkepb "github.com/tink-crypto/tink-go/v2/proto/hpke_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	// publicKeyVersion is the max supported public key version.
	// It must be incremented when support for new versions are implemented.
	publicKeyVersion = 0
	publicKeyTypeURL = "type.googleapis.com/google.crypto.tink.HpkePublicKey"
)

// publicKeyManager implements the KeyManager interface for HybridEncrypt.
type publicKeyManager struct{}

var _ registry.KeyManager = (*publicKeyManager)(nil)

func (p *publicKeyManager) Primitive(serializedKey []byte) (any, error) {
	if len(serializedKey) == 0 {
		return nil, fmt.Errorf("hpke_public_key_manager: empty key size")
	}
	key := new(hpkepb.HpkePublicKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, fmt.Errorf("hpke_public_key_manager: %v", err)
	}
	if err := validatePublicKey(key); err != nil {
		return nil, fmt.Errorf("hpke_public_key_manager: %v", err)
	}
	return hpke.NewEncrypt(key)
}

func (p *publicKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == publicKeyTypeURL
}

func (p *publicKeyManager) TypeURL() string { return publicKeyTypeURL }

func (p *publicKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, fmt.Errorf("hpke_public_key_manager: NewKey is not supported")
}

func (p *publicKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, fmt.Errorf("hpke_public_key_manager: NewKeyData is not supported")
}

func validatePublicKey(key *hpkepb.HpkePublicKey) error {
	if err := keyset.ValidateKeyVersion(key.GetVersion(), publicKeyVersion); err != nil {
		return err
	}
	if err := hpke.ValidatePublicKeyLength(key); err != nil {
		return err
	}
	return validateParams(key.GetParams())
}

func validateParams(params *hpkepb.HpkeParams) error {
	switch params.GetKem() {
	case hpkepb.HpkeKem_DHKEM_P256_HKDF_SHA256:
	case hpkepb.HpkeKem_DHKEM_P384_HKDF_SHA384:
	case hpkepb.HpkeKem_DHKEM_P521_HKDF_SHA512:
	case hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256:
	default:
		return fmt.Errorf("invalid KEM %v", params.GetKem())
	}
	switch params.GetKdf() {
	case hpkepb.HpkeKdf_HKDF_SHA256:
	case hpkepb.HpkeKdf_HKDF_SHA384:
	case hpkepb.HpkeKdf_HKDF_SHA512:
	default:
		return fmt.Errorf("invalid KDF %v", params.GetKdf())
	}
	switch params.GetAead() {
	case hpkepb.HpkeAead_AES_128_GCM:
	case hpkepb.HpkeAead_AES_256_GCM:
	case hpkepb.HpkeAead_CHACHA20_POLY1305:
	default:
		return fmt.Errorf("invalid AEAD %v", params.GetAead())
	}
	return nil
}
