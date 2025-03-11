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
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	_ "github.com/tink-crypto/tink-go/v2/hybrid/hpke" // Import to register the HPKE key managers.
	"github.com/tink-crypto/tink-go/v2/hybrid/internal/hpke"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	hpkepb "github.com/tink-crypto/tink-go/v2/proto/hpke_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	privateKeyVersion = 0
	privateKeyTypeURL = "type.googleapis.com/google.crypto.tink.HpkePrivateKey"
)

func TestPrivateKeyManagerPrimitiveRejectsInvalidPrivateKeyVersion(t *testing.T) {
	km, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}
	params := &hpkepb.HpkeParams{
		Kem:  hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
		Kdf:  hpkepb.HpkeKdf_HKDF_SHA256,
		Aead: hpkepb.HpkeAead_AES_256_GCM,
	}
	_, privKey := pubPrivKeys(t, params)
	privKey.Version = privateKeyVersion + 1
	serializedPrivKey, err := proto.Marshal(privKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.Primitive(serializedPrivKey); err == nil {
		t.Error("Primitive() err = nil, want error")
	}
}

func TestPrivateKeyManagerPrimitiveRejectsInvalidPublicKeyVersion(t *testing.T) {
	km, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}
	params := &hpkepb.HpkeParams{
		Kem:  hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
		Kdf:  hpkepb.HpkeKdf_HKDF_SHA256,
		Aead: hpkepb.HpkeAead_AES_256_GCM,
	}
	_, privKey := pubPrivKeys(t, params)
	privKey.GetPublicKey().Version = publicKeyVersion + 1
	serializedPrivKey, err := proto.Marshal(privKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.Primitive(serializedPrivKey); err == nil {
		t.Error("Primitive() err = nil, want error")
	}
}

func TestPrivateKeyManagerPrimitiveRejectsInvalidParams(t *testing.T) {
	km, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}

	tests := []struct {
		name   string
		params *hpkepb.HpkeParams
	}{
		{
			name: "invalid_kem",
			params: &hpkepb.HpkeParams{
				Kem:  hpkepb.HpkeKem_KEM_UNKNOWN,
				Kdf:  hpkepb.HpkeKdf_HKDF_SHA256,
				Aead: hpkepb.HpkeAead_AES_256_GCM,
			},
		},
		{
			name: "invalid_kdf",
			params: &hpkepb.HpkeParams{
				Kem:  hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
				Kdf:  hpkepb.HpkeKdf_KDF_UNKNOWN,
				Aead: hpkepb.HpkeAead_AES_256_GCM,
			},
		},
		{
			name: "invalid_aead",
			params: &hpkepb.HpkeParams{
				Kem:  hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
				Kdf:  hpkepb.HpkeKdf_HKDF_SHA256,
				Aead: hpkepb.HpkeAead_AEAD_UNKNOWN,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, serializedPrivKey := serializedPubPrivKeys(t, test.params)
			if _, err := km.Primitive(serializedPrivKey); err == nil {
				t.Error("Primitive() err = nil, want error")
			}
		})
	}
}

func TestPrivateKeyManagerPrimitiveRejectsMissingParams(t *testing.T) {
	km, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}
	_, serializedPrivKey := serializedPubPrivKeys(t, nil)
	if _, err := km.Primitive(serializedPrivKey); err == nil {
		t.Error("Primitive() err = nil, want error")
	}
}

func TestPrivateKeyManagerPrimitiveRejectsNilKey(t *testing.T) {
	km, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}
	if _, err := km.Primitive(nil); err == nil {
		t.Error("Primitive() err = nil, want error")
	}
}

func TestPrivateKeyManagerPrimitiveEncryptDecrypt(t *testing.T) {
	km, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}
	pt := random.GetRandomBytes(200)
	ctxInfo := random.GetRandomBytes(100)

	for _, aeadID := range hpkeAEADs {
		params := &hpkepb.HpkeParams{
			Kem:  hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
			Kdf:  hpkepb.HpkeKdf_HKDF_SHA256,
			Aead: aeadID,
		}
		pubKey, privKey := pubPrivKeys(t, params)
		serializedPrivKey, err := proto.Marshal(privKey)
		if err != nil {
			t.Fatal(err)
		}

		enc, err := hpke.NewEncrypt(pubKey)
		if err != nil {
			t.Fatalf("hpke.NewEncrypt() err = %v, want nil", err)
		}
		d, err := km.Primitive(serializedPrivKey)
		if err != nil {
			t.Fatalf("Primitive() err = %v, want nil", err)
		}
		dec, ok := d.(*hpke.Decrypt)
		if !ok {
			t.Fatal("primitive is not Decrypt")
		}

		ct, err := enc.Encrypt(pt, ctxInfo)
		if err != nil {
			t.Fatalf("Encrypt() err = %v, want nil", err)
		}
		gotPT, err := dec.Decrypt(ct, ctxInfo)
		if err != nil {
			t.Fatalf("Decrypt() err = %v, want nil", err)
		}
		if want := pt; !bytes.Equal(gotPT, want) {
			t.Errorf("Decrypt() = %x, want %x", gotPT, want)
		}
	}
}

func TestPrivateKeyManagerNewKeyRejectsNilKeyFormat(t *testing.T) {
	km, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}
	if _, err := km.NewKey(nil); err == nil {
		t.Error("NewKey() err = nil, want error")
	}
}

func TestPrivateKeyManagerNewKeyRejectsInvalidKeyFormat(t *testing.T) {
	km, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}
	serializedKeyFormatUnknownKEM, err := proto.Marshal(
		&hpkepb.HpkeParams{
			Kem:  hpkepb.HpkeKem_KEM_UNKNOWN,
			Kdf:  hpkepb.HpkeKdf_HKDF_SHA256,
			Aead: hpkepb.HpkeAead_AES_256_GCM,
		})
	if err != nil {
		t.Fatal(err)
	}
	serializedKeyFormatUnknownKDF, err := proto.Marshal(
		&hpkepb.HpkeParams{
			Kem:  hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
			Kdf:  hpkepb.HpkeKdf_KDF_UNKNOWN,
			Aead: hpkepb.HpkeAead_AES_256_GCM,
		})
	if err != nil {
		t.Fatal(err)
	}
	serializedKeyFormatUnknownAEAD, err := proto.Marshal(
		&hpkepb.HpkeParams{
			Kem:  hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
			Kdf:  hpkepb.HpkeKdf_HKDF_SHA256,
			Aead: hpkepb.HpkeAead_AEAD_UNKNOWN,
		})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		keyFormat []byte
	}{
		{"kem", serializedKeyFormatUnknownKEM},
		{"kdf", serializedKeyFormatUnknownKDF},
		{"aead", serializedKeyFormatUnknownAEAD},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := km.NewKey(test.keyFormat); err == nil {
				t.Error("NewKey() err = nil, want error")
			}
		})
	}
}

func TestPrivateKeyManagerNewKeyEncryptDecrypt(t *testing.T) {
	km, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}

	wantPT := random.GetRandomBytes(200)
	ctxInfo := random.GetRandomBytes(100)

	for _, kemID := range hpkeKEMs {
		for _, kdfID := range hpkeKDFs {
			for _, aeadID := range hpkeAEADs {
				keyFormat := &hpkepb.HpkeKeyFormat{
					Params: &hpkepb.HpkeParams{
						Kem:  kemID,
						Kdf:  kdfID,
						Aead: aeadID,
					},
				}
				serializedKeyFormat, err := proto.Marshal(keyFormat)
				if err != nil {
					t.Fatal(err)
				}

				privKeyProto, err := km.NewKey(serializedKeyFormat)
				if err != nil {
					t.Fatalf("NewKey() err = %v, want nil", err)
				}
				privKey, ok := privKeyProto.(*hpkepb.HpkePrivateKey)
				if !ok {
					t.Fatal("primitive is not HpkePrivateKey")
				}
				if privKey.GetVersion() != 0 {
					t.Errorf("private key version = %d, want %d", privKey.GetVersion(), 0)
				}
				if len(privKey.GetPrivateKey()) == 0 {
					t.Error("private key is missing")
				}

				pubKey := privKey.GetPublicKey()
				if pubKey.GetVersion() != 0 {
					t.Errorf("public key version = %d, want %d", pubKey.GetVersion(), 0)
				}
				if !cmp.Equal(pubKey.GetParams(), keyFormat.GetParams(), protocmp.Transform()) {
					t.Errorf("key params = %v, want %v", pubKey.GetParams(), keyFormat.GetParams())
				}
				if len(pubKey.GetPublicKey()) == 0 {
					t.Error("public key is missing")
				}

				enc, err := hpke.NewEncrypt(pubKey)
				if err != nil {
					t.Fatalf("hpke.NewEncrypt() err = %v, want nil", err)
				}
				serializedPrivKey, err := proto.Marshal(privKeyProto)
				if err != nil {
					t.Fatal(err)
				}
				d, err := km.Primitive(serializedPrivKey)
				if err != nil {
					t.Fatalf("Primitive() err = %v, want nil", err)
				}
				dec, ok := d.(*hpke.Decrypt)
				if !ok {
					t.Fatal("primitive is not Decrypt")
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

func TestPrivateKeyManagerNewKeyDataRejectsNilKeyFormat(t *testing.T) {
	km, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}
	if _, err := km.NewKeyData(nil); err == nil {
		t.Error("NewKey() err = nil, want error")
	}
}

func TestPrivateKeyManagerNewKeyData(t *testing.T) {
	km, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}

	for _, aeadID := range hpkeAEADs {
		keyFormat := &hpkepb.HpkeKeyFormat{
			Params: &hpkepb.HpkeParams{
				Kem:  hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
				Kdf:  hpkepb.HpkeKdf_HKDF_SHA256,
				Aead: aeadID,
			},
		}
		serializedKeyFormat, err := proto.Marshal(keyFormat)
		if err != nil {
			t.Fatal(err)
		}

		keyData, err := km.NewKeyData(serializedKeyFormat)
		if err != nil {
			t.Fatalf("NewKeyData() err = %v, want nil", err)
		}
		if got, want := keyData.GetTypeUrl(), privateKeyTypeURL; got != want {
			t.Errorf("type URL = %q, want %q", got, want)
		}
		if got, want := keyData.GetKeyMaterialType(), tinkpb.KeyData_ASYMMETRIC_PRIVATE; got != want {
			t.Errorf("key material type = %d, want %d", got, want)
		}

		privKey := new(hpkepb.HpkePrivateKey)
		if err := proto.Unmarshal(keyData.GetValue(), privKey); err != nil {
			t.Fatalf("Unmarshal err = %v, want nil", err)
		}
		if privKey.GetVersion() != 0 {
			t.Errorf("private key version = %d, want %d", privKey.GetVersion(), 0)
		}
		if len(privKey.GetPrivateKey()) == 0 {
			t.Error("private key is missing")
		}

		pubKey := privKey.GetPublicKey()
		if pubKey.GetVersion() != 0 {
			t.Errorf("public key version = %d, want %d", pubKey.GetVersion(), 0)
		}
		if !cmp.Equal(pubKey.GetParams(), keyFormat.GetParams(), protocmp.Transform()) {
			t.Errorf("key params = %v, want %v", pubKey.GetParams(), keyFormat.GetParams())
		}
		if len(pubKey.GetPublicKey()) == 0 {
			t.Error("public key is missing")
		}
	}
}

func TestPrivateKeyManagerPublicKeyDataRejectsInvalidPrivateKeyVersion(t *testing.T) {
	k, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}
	km, ok := k.(registry.PrivateKeyManager)
	if !ok {
		t.Errorf("primitive is not PrivateKeyManager")
	}
	params := &hpkepb.HpkeParams{
		Kem:  hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
		Kdf:  hpkepb.HpkeKdf_HKDF_SHA256,
		Aead: hpkepb.HpkeAead_AES_256_GCM,
	}
	_, privKey := pubPrivKeys(t, params)
	privKey.Version = privateKeyVersion + 1
	serializedPrivKey, err := proto.Marshal(privKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.PublicKeyData(serializedPrivKey); err == nil {
		t.Error("PublicKeyData() err = nil, want error")
	}
}

func TestPrivateKeyManagerPublicKeyDataRejectsInvalidPublicKeyVersion(t *testing.T) {
	k, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}
	km, ok := k.(registry.PrivateKeyManager)
	if !ok {
		t.Errorf("primitive is not PrivateKeyManager")
	}
	params := &hpkepb.HpkeParams{
		Kem:  hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
		Kdf:  hpkepb.HpkeKdf_HKDF_SHA256,
		Aead: hpkepb.HpkeAead_AES_256_GCM,
	}
	_, privKey := pubPrivKeys(t, params)
	privKey.GetPublicKey().Version = publicKeyVersion + 1
	serializedPrivKey, err := proto.Marshal(privKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.PublicKeyData(serializedPrivKey); err == nil {
		t.Error("PublicKeyData() err = nil, want error")
	}
}

func TestPrivateKeyManagerPublicKeyDataRejectsNilKey(t *testing.T) {
	k, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}
	km, ok := k.(registry.PrivateKeyManager)
	if !ok {
		t.Errorf("primitive is not PrivateKeyManager")
	}
	if _, err := km.PublicKeyData(nil); err == nil {
		t.Errorf("PublicKeyData() err = nil, want error")
	}
}

func TestPrivateKeyManagerPublicKeyData(t *testing.T) {
	k, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}
	km, ok := k.(registry.PrivateKeyManager)
	if !ok {
		t.Errorf("primitive is not PrivateKeyManager")
	}

	params := &hpkepb.HpkeParams{
		Kem:  hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
		Kdf:  hpkepb.HpkeKdf_HKDF_SHA256,
		Aead: hpkepb.HpkeAead_AES_256_GCM,
	}
	_, privKey := pubPrivKeys(t, params)
	serializedPrivKey, err := proto.Marshal(privKey)
	if err != nil {
		t.Fatal(err)
	}
	wantPubKey := privKey.GetPublicKey()
	serializedPubKey, err := proto.Marshal(wantPubKey)
	if err != nil {
		t.Fatal(err)
	}

	pubKey, err := km.PublicKeyData(serializedPrivKey)
	if err != nil {
		t.Fatalf("PublicKeyData() err = %v, want nil", err)
	}
	if got, want := pubKey.GetTypeUrl(), publicKeyTypeURL; got != want {
		t.Errorf("type URL = %q, want %q", got, want)
	}
	if !bytes.Equal(pubKey.GetValue(), serializedPubKey) {
		t.Errorf("value = %v, want %v", pubKey.GetValue(), serializedPubKey)
	}
	if got, want := pubKey.GetKeyMaterialType(), tinkpb.KeyData_ASYMMETRIC_PUBLIC; got != want {
		t.Errorf("Key material type = %d, want %d", got, want)
	}
}

func TestPrivateKeyManagerDoesSupport(t *testing.T) {
	km, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}
	if !km.DoesSupport(privateKeyTypeURL) {
		t.Errorf("DoesSupport(%q) = false, want true", privateKeyTypeURL)
	}
	unsupportedKeyTypeURL := "unsupported.key.type"
	if km.DoesSupport(unsupportedKeyTypeURL) {
		t.Errorf("DoesSupport(%q) = true, want false", unsupportedKeyTypeURL)
	}
}

func TestPrivateKeyManagerTypeURL(t *testing.T) {
	km, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}
	if km.TypeURL() != privateKeyTypeURL {
		t.Errorf("TypeURL = %q, want %q", km.TypeURL(), privateKeyTypeURL)
	}
}
