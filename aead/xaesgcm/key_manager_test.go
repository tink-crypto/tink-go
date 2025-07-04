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
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/aead/internal/testutil"
	"github.com/tink-crypto/tink-go/v2/aead/xaesgcm"

	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
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
	if err := testutil.EncryptDecrypt(xAESGCM, wantXAESGCM); err != nil {
		t.Errorf("testutil.EncryptDecrypt(xAESGCM, wantXAESGCM) err = %v, want nil", err)
	}
	if err := testutil.EncryptDecrypt(wantXAESGCM, xAESGCM); err != nil {
		t.Errorf("testutil.EncryptDecrypt(wantXAESGCM, xAESGCM) err = %v, want nil", err)
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
	if err := validateXAESGCMKey(t, key); err != nil {
		t.Errorf("validateXAESGCMKey(t, %v) = %v; want nil", key, err)
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
	if err := validateXAESGCMKey(t, key); err != nil {
		t.Errorf("validateXAESGCMKey(t, %v) = %v; want nil", key, err)
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

func validateXAESGCMKey(t *testing.T, key *xaesgcmpb.XAesGcmKey) error {
	if key.Version != 0 {
		return fmt.Errorf("incorrect key version: keyVersion != %d", 0)
	}
	if uint32(len(key.KeyValue)) != 32 {
		return fmt.Errorf("incorrect key size: keySize != %d", 32)
	}
	// Try to create a primitive and encrypt and decrypt.
	p, err := xaesgcm.NewAEAD(mustCreateKey(t, key.GetKeyValue(), xaesgcm.VariantNoPrefix, 12, 0), internalapi.Token{})
	if err != nil {
		return err
	}
	return testutil.EncryptDecrypt(p, p)
}
