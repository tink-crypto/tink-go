// Copyright 2024 Google LLC
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

package xaesgcm_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/aead/subtle"
	"github.com/tink-crypto/tink-go/v2/aead/xaesgcm"

	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/internalregistry"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/tink"
	tpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	xaesgcmpb "github.com/tink-crypto/tink-go/v2/proto/x_aes_gcm_go_proto"
)

const (
	typeURL = "type.googleapis.com/google.crypto.tink.XAesGcmKey"
)

func TestKeyManagerGetPrimitive(t *testing.T) {
	km, err := registry.GetKeyManager(typeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager(%s) err = %v, want nil", typeURL, err)
	}
	key := &xaesgcmpb.XAesGcmKey{
		Version:  0,
		KeyValue: random.GetRandomBytes(32),
		Params: &xaesgcmpb.XAesGcmParams{
			SaltSize: 12,
		},
	}
	serializedKey := mustMarshalProto(t, key)
	p, err := km.Primitive(serializedKey)
	if err != nil {
		t.Errorf("km.Primitive(%v) = %v; want nil", serializedKey, err)
	}
	xAESGCM, ok := p.(tink.AEAD)
	if !ok {
		t.Fatalf("km.Primitive(serializedKey) = %T, want tink.AEAD", p)
	}

	wantXAESGCM, err := xaesgcm.NewAEAD(mustCreateKey(t, key.GetKeyValue(), xaesgcm.VariantNoPrefix, 12, 0), internalapi.Token{})
	if err != nil {
		t.Fatalf("xaesgcm.NewAEAD() err = %v, want nil", err)
	}
	if err := encryptDecrypt(xAESGCM, wantXAESGCM); err != nil {
		t.Errorf("encryptDecrypt(xAESGCM, wantXAESGCM) err = %v, want nil", err)
	}
	if err := encryptDecrypt(wantXAESGCM, xAESGCM); err != nil {
		t.Errorf("encryptDecrypt(wantXAESGCM, xAESGCM) err = %v, want nil", err)
	}
}

func TestKeyManagerGetPrimitiveWithInvalidKeys(t *testing.T) {
	km, err := registry.GetKeyManager(typeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager(%s) err = %v, want nil", typeURL, err)
	}
	for _, tc := range []struct {
		name string
		key  *xaesgcmpb.XAesGcmKey
	}{
		{
			name: "bad key size (17)",
			key: &xaesgcmpb.XAesGcmKey{
				Version:  0,
				KeyValue: random.GetRandomBytes(17),
				Params: &xaesgcmpb.XAesGcmParams{
					SaltSize: 12,
				},
			},
		},
		{
			name: "bad key size (25)",
			key: &xaesgcmpb.XAesGcmKey{
				Version:  0,
				KeyValue: random.GetRandomBytes(25),
				Params: &xaesgcmpb.XAesGcmParams{
					SaltSize: 12,
				},
			},
		},
		{
			name: "bad key size (33)",
			key: &xaesgcmpb.XAesGcmKey{
				Version:  0,
				KeyValue: random.GetRandomBytes(33),
				Params: &xaesgcmpb.XAesGcmParams{
					SaltSize: 12,
				},
			},
		},
		{
			name: "bad key version",
			key: &xaesgcmpb.XAesGcmKey{
				Version:  0 + 1,
				KeyValue: random.GetRandomBytes(32),
				Params: &xaesgcmpb.XAesGcmParams{
					SaltSize: 12,
				},
			},
		},
		{
			name: "bad salt size",
			key: &xaesgcmpb.XAesGcmKey{
				Version:  0,
				KeyValue: random.GetRandomBytes(32),
				Params: &xaesgcmpb.XAesGcmParams{
					SaltSize: 7,
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serializedKey := mustMarshalProto(t, tc.key)
			if _, err := km.Primitive(serializedKey); err == nil {
				t.Errorf("km.Primitive(%v) err = nil, want non-nil", serializedKey)
			}
		})
	}
}

func TestKeyManagerNewKey(t *testing.T) {
	km, err := registry.GetKeyManager(typeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager(%s) err = %v, want nil", typeURL, err)
	}
	keyFormat := &xaesgcmpb.XAesGcmKeyFormat{
		Version: 0,
		Params: &xaesgcmpb.XAesGcmParams{
			SaltSize: 12,
		},
	}
	serializedKeyFormat := mustMarshalProto(t, keyFormat)
	m, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		t.Fatalf("km.NewKey(serializedKeyFormat) = _, %v; want _, nil", err)
	}
	key, ok := m.(*xaesgcmpb.XAesGcmKey)
	if !ok {
		t.Errorf("m is not a *xaesgcmpb.XAesGcmKey")
	}
	if err := validateXAESGCMKey(key); err != nil {
		t.Errorf("validateXAESGCMKey(%v) = %v; want nil", key, err)
	}
}

func TestKeyManagerNewKeyData(t *testing.T) {
	km, err := registry.GetKeyManager(typeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager(%s) err = %v, want nil", typeURL, err)
	}
	keyFormat := &xaesgcmpb.XAesGcmKeyFormat{
		Version: 0,
		Params: &xaesgcmpb.XAesGcmParams{
			SaltSize: 12,
		},
	}
	serializedKeyFormat := mustMarshalProto(t, keyFormat)
	kd, err := km.NewKeyData(serializedKeyFormat)
	if err != nil {
		t.Errorf("km.NewKeyData(serializedKeyFormat) = _, %v; want _, nil", err)
	}
	if kd.TypeUrl != typeURL {
		t.Errorf("TypeUrl: %v != %v", kd.TypeUrl, typeURL)
	}
	if kd.KeyMaterialType != tpb.KeyData_SYMMETRIC {
		t.Errorf("KeyMaterialType: %v != SYMMETRIC", kd.KeyMaterialType)
	}
	key := new(xaesgcmpb.XAesGcmKey)
	if err := proto.Unmarshal(kd.Value, key); err != nil {
		t.Errorf("proto.Unmarshal(%v, key) = %v; want nil", kd.Value, err)
	}
	if err := validateXAESGCMKey(key); err != nil {
		t.Errorf("validateXAESGCMKey(%v) = %v; want nil", key, err)
	}
	p, err := registry.PrimitiveFromKeyData(kd)
	if err != nil {
		t.Errorf("registry.PrimitiveFromKeyData(kd) err = %v, want nil", err)
	}
	_, ok := p.(tink.AEAD)
	if !ok {
		t.Error("registry.PrimitiveFromKeyData(kd) did not return a tink.AEAD primitive")
	}
}

func TestKeyManagerDoesSupport(t *testing.T) {
	km, err := registry.GetKeyManager(typeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager(%s) err = %v, want nil", typeURL, err)
	}
	if !km.DoesSupport(typeURL) {
		t.Errorf("XAESGCMKeyManager must support %s", typeURL)
	}
	if km.DoesSupport("some bad type") {
		t.Errorf("XAESGCMKeyManager must only support %s", typeURL)
	}
}

func TestKeyManagerTypeURL(t *testing.T) {
	km, err := registry.GetKeyManager(typeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager(%s) err = %v, want nil", typeURL, err)
	}
	if kt := km.TypeURL(); kt != typeURL {
		t.Errorf("km.TypeURL() = %s; want %s", kt, typeURL)
	}
}

func TestKeyManagerKeyMaterialType(t *testing.T) {
	km, err := registry.GetKeyManager(typeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", typeURL, err)
	}
	keyManager, ok := km.(internalregistry.DerivableKeyManager)
	if !ok {
		t.Fatalf("key manager is not DerivableKeyManager")
	}
	if got, want := keyManager.KeyMaterialType(), tpb.KeyData_SYMMETRIC; got != want {
		t.Errorf("KeyMaterialType() = %v, want %v", got, want)
	}
}

func TestKeyManagerDeriveKey(t *testing.T) {
	km, err := registry.GetKeyManager(typeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", typeURL, err)
	}
	keyManager, ok := km.(internalregistry.DerivableKeyManager)
	if !ok {
		t.Fatalf("key manager is not DerivableKeyManager")
	}
	keyFormat := mustMarshalProto(t, &xaesgcmpb.XAesGcmKeyFormat{
		Version: 0,
		Params: &xaesgcmpb.XAesGcmParams{
			SaltSize: 12,
		},
	})
	for _, test := range []struct {
		name      string
		keyFormat []byte
	}{
		{
			name:      "specified",
			keyFormat: keyFormat,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			rand := random.GetRandomBytes(32)
			buf := &bytes.Buffer{}
			buf.Write(rand) // never returns a non-nil error
			k, err := keyManager.DeriveKey(test.keyFormat, buf)
			if err != nil {
				t.Fatalf("keyManager.DeriveKey() err = %v, want nil", err)
			}
			key := k.(*xaesgcmpb.XAesGcmKey)
			want := &xaesgcmpb.XAesGcmKey{
				Version:  0,
				KeyValue: rand,
				Params: &xaesgcmpb.XAesGcmParams{
					SaltSize: 12,
				},
			}
			if diff := cmp.Diff(key, want, protocmp.Transform()); diff != "" {
				t.Errorf("incorrect derived key: diff = %v", diff)
			}
		})
	}
}

func TestKeyManagerDeriveKeyFailsWithInvalidKeyFormats(t *testing.T) {
	km, err := registry.GetKeyManager(typeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", typeURL, err)
	}
	keyManager, ok := km.(internalregistry.DerivableKeyManager)
	if !ok {
		t.Fatalf("key manager is not DerivableKeyManager")
	}
	for _, test := range []struct {
		name      string
		keyFormat []byte
	}{
		{
			name:      "nil",
			keyFormat: nil,
		},
		{
			name:      "empty",
			keyFormat: []byte{},
		},
		{
			name: "invalid version",
			keyFormat: mustMarshalProto(t, &xaesgcmpb.XAesGcmKeyFormat{
				Version: 10,
				Params: &xaesgcmpb.XAesGcmParams{
					SaltSize: 12,
				},
			}),
		},
		{
			// Proto messages start with a VarInt, which always ends with a byte with the
			// MSB unset, so 0x80 is invalid.
			name:      "invalid serialization",
			keyFormat: mustHexDecode(t, "80"),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			buf := bytes.NewBuffer(random.GetRandomBytes(32))
			if _, err := keyManager.DeriveKey(test.keyFormat, buf); err == nil {
				t.Errorf("keyManager.DeriveKey() err = nil, want non-nil")
			}
		})
	}
}

func TestKeyManagerDeriveKeyFailsWithInsufficientRandomness(t *testing.T) {
	km, err := registry.GetKeyManager(typeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", typeURL, err)
	}
	keyManager, ok := km.(internalregistry.DerivableKeyManager)
	if !ok {
		t.Fatalf("key manager is not DerivableKeyManager")
	}
	keyFormat := mustMarshalProto(t, &xaesgcmpb.XAesGcmKeyFormat{
		Version: 0,
		Params: &xaesgcmpb.XAesGcmParams{
			SaltSize: 12,
		},
	})
	{
		buf := bytes.NewBuffer(random.GetRandomBytes(32))
		if _, err := keyManager.DeriveKey(keyFormat, buf); err != nil {
			t.Errorf("keyManager.DeriveKey() err = %v, want nil", err)
		}
	}
	{
		insufficientBuf := bytes.NewBuffer(random.GetRandomBytes(32 - 1))
		if _, err := keyManager.DeriveKey(keyFormat, insufficientBuf); err == nil {
			t.Errorf("keyManager.DeriveKey() err = nil, want non-nil")
		}
	}
}

func encryptDecrypt(encryptor, decryptor tink.AEAD) error {
	// Try to encrypt and decrypt random data.
	pt := random.GetRandomBytes(32)
	aad := random.GetRandomBytes(32)
	ct, err := encryptor.Encrypt(pt, aad)
	if err != nil {
		return fmt.Errorf("encryptor.Encrypt() err = %v, want nil", err)
	}
	decrypted, err := decryptor.Decrypt(ct, aad)
	if err != nil {
		return fmt.Errorf("decryptor.Decrypt() err = %v, want nil", err)
	}
	if !bytes.Equal(decrypted, pt) {
		return fmt.Errorf("decryptor.Decrypt() = %v, want %v", decrypted, pt)
	}
	return nil
}

func validateXAESGCMKey(key *xaesgcmpb.XAesGcmKey) error {
	if key.Version != 0 {
		return fmt.Errorf("incorrect key version: keyVersion != %d", 0)
	}
	if uint32(len(key.KeyValue)) != 32 {
		return fmt.Errorf("incorrect key size: keySize != %d", 32)
	}

	// Try to encrypt and decrypt.
	p, err := subtle.NewXChaCha20Poly1305(key.KeyValue)
	if err != nil {
		return fmt.Errorf("invalid key: %v", key.KeyValue)
	}
	return encryptDecrypt(p, p)
}
