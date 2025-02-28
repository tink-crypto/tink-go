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

package hpke_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/hybrid/internal/hpke"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/subtle"
	hpkepb "github.com/tink-crypto/tink-go/v2/proto/hpke_go_proto"
)

const (
	publicKeyVersion = 0
	publicKeyTypeURL = "type.googleapis.com/google.crypto.tink.HpkePublicKey"
)

var hpkeKEMs = []hpkepb.HpkeKem{
	hpkepb.HpkeKem_DHKEM_P256_HKDF_SHA256,
	hpkepb.HpkeKem_DHKEM_P384_HKDF_SHA384,
	hpkepb.HpkeKem_DHKEM_P521_HKDF_SHA512,
	hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
}

var hpkeKDFs = []hpkepb.HpkeKdf{
	hpkepb.HpkeKdf_HKDF_SHA256,
	hpkepb.HpkeKdf_HKDF_SHA384,
	hpkepb.HpkeKdf_HKDF_SHA512,
}

var hpkeAEADs = []hpkepb.HpkeAead{
	hpkepb.HpkeAead_AES_128_GCM,
	hpkepb.HpkeAead_AES_256_GCM,
	hpkepb.HpkeAead_CHACHA20_POLY1305,
}

func TestPublicKeyManagerPrimitiveRejectsInvalidKeyVersion(t *testing.T) {
	km, err := registry.GetKeyManager(publicKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", publicKeyTypeURL, err)
	}
	params := &hpkepb.HpkeParams{
		Kem:  hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
		Kdf:  hpkepb.HpkeKdf_HKDF_SHA256,
		Aead: hpkepb.HpkeAead_AES_256_GCM,
	}
	pubKey, _ := pubPrivKeys(t, params)
	pubKey.Version = 1
	serializedPubKey, err := proto.Marshal(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.Primitive(serializedPubKey); err == nil {
		t.Error("Primitive() err = nil, want error")
	}
}

func TestPublicKeyManagerPrimitiveRejectsInvalidParams(t *testing.T) {
	km, err := registry.GetKeyManager(publicKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", publicKeyTypeURL, err)
	}

	tests := []struct {
		name   string
		params *hpkepb.HpkeParams
	}{
		{"kem", &hpkepb.HpkeParams{
			Kem:  hpkepb.HpkeKem_KEM_UNKNOWN,
			Kdf:  hpkepb.HpkeKdf_HKDF_SHA256,
			Aead: hpkepb.HpkeAead_AES_256_GCM,
		}},
		{"kdf", &hpkepb.HpkeParams{
			Kem:  hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
			Kdf:  hpkepb.HpkeKdf_KDF_UNKNOWN,
			Aead: hpkepb.HpkeAead_AES_256_GCM,
		}},
		{"aead", &hpkepb.HpkeParams{
			Kem:  hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
			Kdf:  hpkepb.HpkeKdf_HKDF_SHA256,
			Aead: hpkepb.HpkeAead_AEAD_UNKNOWN,
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			serializedPubKey, _ := serializedPubPrivKeys(t, test.params)
			if _, err := km.Primitive(serializedPubKey); err == nil {
				t.Error("Primitive() err = nil, want error")
			}
		})
	}
}

func TestPublicKeyManagerPrimitiveRejectsMissingParams(t *testing.T) {
	km, err := registry.GetKeyManager(publicKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", publicKeyTypeURL, err)
	}
	serializedPubKey, _ := serializedPubPrivKeys(t, nil)
	if _, err := km.Primitive(serializedPubKey); err == nil {
		t.Error("Primitive() err = nil, want error")
	}
}

func TestPublicKeyManagerPrimitiveRejectsNilKey(t *testing.T) {
	km, err := registry.GetKeyManager(publicKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", publicKeyTypeURL, err)
	}
	if _, err := km.Primitive(nil); err == nil {
		t.Error("Primitive() err = nil, want error")
	}
}

func TestPublicKeyManagerPrimitiveEncryptDecrypt(t *testing.T) {
	km, err := registry.GetKeyManager(publicKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", publicKeyTypeURL, err)
	}

	wantPT := random.GetRandomBytes(200)
	ctxInfo := random.GetRandomBytes(100)

	for _, kemID := range hpkeKEMs {
		for _, kdfID := range hpkeKDFs {
			for _, aeadID := range hpkeAEADs {
				params := &hpkepb.HpkeParams{
					Kem:  kemID,
					Kdf:  kdfID,
					Aead: aeadID,
				}
				pubKey, privKey := pubPrivKeys(t, params)
				serializedPubKey, err := proto.Marshal(pubKey)
				if err != nil {
					t.Fatal(err)
				}

				e, err := km.Primitive(serializedPubKey)
				if err != nil {
					t.Fatalf("Primitive() err = %v, want nil", err)
				}
				enc, ok := e.(*hpke.Encrypt)
				if !ok {
					t.Fatal("primitive is not Encrypt")
				}
				dec, err := hpke.NewDecrypt(privKey)
				if err != nil {
					t.Fatalf("hpke.NewDecrypt() err = %v, want nil", err)
				}

				ct, err := enc.Encrypt(wantPT, ctxInfo)
				if err != nil {
					t.Fatalf("Encrypt() err = %v, want nil", err)
				}
				gotPT, err := dec.Decrypt(ct, ctxInfo)
				if err != nil {
					t.Fatalf("Decrypt() err = %v, want nil", err)
				}
				if !bytes.Equal(gotPT, wantPT) {
					t.Errorf("Decrypt() = %x, want %x", gotPT, wantPT)
				}
			}
		}
	}
}

func TestPublicKeyManagerDoesSupport(t *testing.T) {
	km, err := registry.GetKeyManager(publicKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", publicKeyTypeURL, err)
	}
	if !km.DoesSupport(publicKeyTypeURL) {
		t.Errorf("DoesSupport(%q) = false, want true", publicKeyTypeURL)
	}
	unsupportedKeyTypeURL := "unsupported.key.type"
	if km.DoesSupport(unsupportedKeyTypeURL) {
		t.Errorf("DoesSupport(%q) = true, want false", unsupportedKeyTypeURL)
	}
}

func TestPublicKeyManagerTypeURL(t *testing.T) {
	km, err := registry.GetKeyManager(publicKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", publicKeyTypeURL, err)
	}
	if km.TypeURL() != publicKeyTypeURL {
		t.Errorf("TypeURL = %q, want %q", km.TypeURL(), publicKeyTypeURL)
	}
}

func TestPublicKeyManagerNotSupported(t *testing.T) {
	km, err := registry.GetKeyManager(publicKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", publicKeyTypeURL, err)
	}
	if _, err := km.NewKey(nil); err == nil {
		t.Error("NewKey(nil) err = nil, want error")
	}
	if _, err := km.NewKeyData(nil); err == nil {
		t.Error("NewKeyData(nil) err = nil, want error")
	}
}

func serializedPubPrivKeys(t *testing.T, params *hpkepb.HpkeParams) ([]byte, []byte) {
	t.Helper()
	pub, priv := pubPrivKeys(t, params)
	serializedPub, err := proto.Marshal(pub)
	if err != nil {
		t.Fatal(err)
	}
	serializedPriv, err := proto.Marshal(priv)
	if err != nil {
		t.Fatal(err)
	}
	return serializedPub, serializedPriv
}

func pubPrivKeys(t *testing.T, params *hpkepb.HpkeParams) (*hpkepb.HpkePublicKey, *hpkepb.HpkePrivateKey) {
	t.Helper()

	var privKeyBytes, pubKeyBytes []byte
	switch params.GetKem() {
	case hpkepb.HpkeKem_DHKEM_P256_HKDF_SHA256:
		privKey, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ecdh.P256().GenerateKey: err %q", err)
		}
		privKeyBytes = privKey.Bytes()
		pubKeyBytes = privKey.PublicKey().Bytes()
	case hpkepb.HpkeKem_DHKEM_P384_HKDF_SHA384:
		privKey, err := ecdh.P384().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ecdh.P384().GenerateKey: err %q", err)
		}
		privKeyBytes = privKey.Bytes()
		pubKeyBytes = privKey.PublicKey().Bytes()
	case hpkepb.HpkeKem_DHKEM_P521_HKDF_SHA512:
		privKey, err := ecdh.P521().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ecdh.P521().GenerateKey: err %q", err)
		}
		privKeyBytes = privKey.Bytes()
		pubKeyBytes = privKey.PublicKey().Bytes()
	case hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256:
		var err error
		privKeyBytes, err = subtle.GeneratePrivateKeyX25519()
		if err != nil {
			t.Fatalf("GeneratePrivateKeyX25519: err %q", err)
		}
		pubKeyBytes, err = subtle.PublicFromPrivateX25519(privKeyBytes)
		if err != nil {
			t.Fatalf("PublicFromPrivateX25519: err %q", err)
		}
	default:
		// Create invalid keys for testing.
	}

	pubKey := &hpkepb.HpkePublicKey{
		Version:   0,
		Params:    params,
		PublicKey: pubKeyBytes,
	}
	privKey := &hpkepb.HpkePrivateKey{
		Version:    0,
		PublicKey:  pubKey,
		PrivateKey: privKeyBytes,
	}
	return pubKey, privKey
}
