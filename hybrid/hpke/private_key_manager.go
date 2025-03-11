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
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/hybrid/internal/hpke"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/subtle"
	hpkepb "github.com/tink-crypto/tink-go/v2/proto/hpke_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	privateKeyVersion = 0
	privateKeyTypeURL = "type.googleapis.com/google.crypto.tink.HpkePrivateKey"
)

// privateKeyManager implements the KeyManager interface for HybridDecrypt.
type privateKeyManager struct{}

var _ registry.PrivateKeyManager = (*privateKeyManager)(nil)

func (p *privateKeyManager) Primitive(serializedKey []byte) (any, error) {
	if len(serializedKey) == 0 {
		return nil, fmt.Errorf("hpke_private_key_manager: empty key size")
	}
	key := new(hpkepb.HpkePrivateKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, fmt.Errorf("hpke_private_key_manager: %v", err)
	}
	if err := validatePrivateKey(key); err != nil {
		return nil, err
	}
	return hpke.NewDecrypt(key)
}

// NewKey returns a set of private and public keys of key version 0.
func (p *privateKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, fmt.Errorf("hpke_private_key_manager: empty key format size")
	}
	keyFormat := new(hpkepb.HpkeKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("hpke_private_key_manager: %v", err)
	}
	if err := validateKeyFormat(keyFormat); err != nil {
		return nil, err
	}

	var privKeyBytes, pubKeyBytes []byte
	switch keyFormat.GetParams().GetKem() {
	case hpkepb.HpkeKem_DHKEM_P256_HKDF_SHA256:
		privKey, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("hpke_private_key_manager: generate P-256 private key: %v", err)
		}
		privKeyBytes = privKey.Bytes()
		pubKeyBytes = privKey.PublicKey().Bytes()
	case hpkepb.HpkeKem_DHKEM_P384_HKDF_SHA384:
		privKey, err := ecdh.P384().GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("hpke_private_key_manager: generate P-384 private key: %v", err)
		}
		privKeyBytes = privKey.Bytes()
		pubKeyBytes = privKey.PublicKey().Bytes()
	case hpkepb.HpkeKem_DHKEM_P521_HKDF_SHA512:
		privKey, err := ecdh.P521().GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("hpke_private_key_manager: generate P-521 private key: %v", err)
		}
		privKeyBytes = privKey.Bytes()
		pubKeyBytes = privKey.PublicKey().Bytes()
	case hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256:
		var err error
		privKeyBytes, err = subtle.GeneratePrivateKeyX25519()
		if err != nil {
			return nil, fmt.Errorf("hpke_private_key_manager: generate X25519 private key: %v", err)
		}
		pubKeyBytes, err = subtle.PublicFromPrivateX25519(privKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("hpke_private_key_manager: get X25519 public key from private key: %v", err)
		}
	default:
		return nil, fmt.Errorf("hpke_private_key_manager: unsupported KEM: %v", keyFormat.GetParams().GetKem())
	}

	return &hpkepb.HpkePrivateKey{
		Version: 0,
		PublicKey: &hpkepb.HpkePublicKey{
			Version:   0,
			Params:    keyFormat.GetParams(),
			PublicKey: pubKeyBytes,
		},
		PrivateKey: privKeyBytes,
	}, nil
}

func (p *privateKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := p.NewKey(serializedKeyFormat)
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

func (p *privateKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	if len(serializedPrivKey) == 0 {
		return nil, fmt.Errorf("hpke_private_key_manager: empty key size")
	}
	privKey := new(hpkepb.HpkePrivateKey)
	if err := proto.Unmarshal(serializedPrivKey, privKey); err != nil {
		return nil, fmt.Errorf("hpke_private_key_manager: %v", err)
	}
	if err := validatePrivateKey(privKey); err != nil {
		return nil, err
	}
	serializedPubKey, err := proto.Marshal(privKey.GetPublicKey())
	if err != nil {
		return nil, fmt.Errorf("hpke_private_key_manager: %v", err)
	}
	return &tinkpb.KeyData{
		TypeUrl:         publicKeyTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

func (p *privateKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == privateKeyTypeURL
}

func (p *privateKeyManager) TypeURL() string { return privateKeyTypeURL }

func validatePrivateKey(key *hpkepb.HpkePrivateKey) error {
	if err := keyset.ValidateKeyVersion(key.GetVersion(), privateKeyVersion); err != nil {
		return err
	}
	if err := hpke.ValidatePrivateKeyLength(key); err != nil {
		return err
	}
	return validatePublicKey(key.GetPublicKey())
}

func validateKeyFormat(kf *hpkepb.HpkeKeyFormat) error {
	return validateParams(kf.GetParams())
}
