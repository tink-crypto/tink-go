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

package aesctrhmac_test

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/aead"
	aeadtestutil "github.com/tink-crypto/tink-go/v2/aead/internal/testutil"
	"github.com/tink-crypto/tink-go/v2/aead/subtle"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	subtleMac "github.com/tink-crypto/tink-go/v2/mac/subtle"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"
	ctrpb "github.com/tink-crypto/tink-go/v2/proto/aes_ctr_go_proto"
	achpb "github.com/tink-crypto/tink-go/v2/proto/aes_ctr_hmac_aead_go_proto"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	hmacpb "github.com/tink-crypto/tink-go/v2/proto/hmac_go_proto"
)

func TestKeyManagerNewKeyMultipleTimes(t *testing.T) {
	keyTemplate := aead.AES128CTRHMACSHA256KeyTemplate()
	aeadKeyFormat := new(achpb.AesCtrHmacAeadKeyFormat)
	if err := proto.Unmarshal(keyTemplate.Value, aeadKeyFormat); err != nil {
		t.Fatalf("proto.Unmarshal(keyTemplate.Value, aeadKeyFormat) err = %v, want nil", err)
	}

	keyManager, err := registry.GetKeyManager(testutil.AESCTRHMACAEADTypeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager(%s) err = %v, want nil", testutil.AESCTRHMACAEADTypeURL, err)
	}

	keys := make(map[string]bool)
	const numTests = 24
	for i := 0; i < numTests/2; i++ {
		k, err := keyManager.NewKey(keyTemplate.Value)
		if err != nil {
			t.Fatalf("keyManager.NewKey() err = %q, want nil", err)
		}
		sk, err := proto.Marshal(k)
		if err != nil {
			t.Fatalf("cannot serialize key, error: %v", err)
		}

		key := new(achpb.AesCtrHmacAeadKey)
		proto.Unmarshal(sk, key)

		keys[string(key.AesCtrKey.KeyValue)] = true
		keys[string(key.HmacKey.KeyValue)] = true
		if len(key.AesCtrKey.KeyValue) != 16 {
			t.Errorf("unexpected AES key size, got: %d, want: 16", len(key.AesCtrKey.KeyValue))
		}
		if len(key.HmacKey.KeyValue) != 32 {
			t.Errorf("unexpected HMAC key size, got: %d, want: 32", len(key.HmacKey.KeyValue))
		}
	}
	if len(keys) != numTests {
		t.Errorf("unexpected number of keys in set, got: %d, want: %d", len(keys), numTests)
	}
}

func TestKeyManagerNewKeyWithInvalidSerializedKeyFormat(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESCTRHMACAEADTypeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager(%s) err = %v, want nil", testutil.AESCTRHMACAEADTypeURL, err)
	}

	keyFormatWithNilParams := &achpb.AesCtrHmacAeadKeyFormat{
		AesCtrKeyFormat: &ctrpb.AesCtrKeyFormat{
			Params:  nil,
			KeySize: 32,
		},
		HmacKeyFormat: &hmacpb.HmacKeyFormat{
			Params:  nil,
			KeySize: 32,
		},
	}
	serializedKeyFormatWithNilParams, err := proto.Marshal(keyFormatWithNilParams)
	if err != nil {
		t.Fatalf("failed to marshal key: %s", err)
	}

	keyFormatWithNilNestedKeyFormats := &achpb.AesCtrHmacAeadKeyFormat{
		AesCtrKeyFormat: nil,
		HmacKeyFormat:   nil,
	}
	serializedKeyFormatWithNilNestedKeyFormats, err := proto.Marshal(keyFormatWithNilNestedKeyFormats)
	if err != nil {
		t.Fatalf("failed to marshal key: %s", err)
	}

	testcases := []struct {
		name                string
		serializedKeyFormat []byte
	}{
		{
			name:                "nil",
			serializedKeyFormat: nil,
		},
		{
			name:                "empty slice",
			serializedKeyFormat: []byte{},
		},
		{
			name:                "slice with invalid data",
			serializedKeyFormat: make([]byte, 128),
		},
		{
			name:                "unset params",
			serializedKeyFormat: serializedKeyFormatWithNilParams,
		},
		{
			name:                "unset nested key formats",
			serializedKeyFormat: serializedKeyFormatWithNilNestedKeyFormats,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			_, err = keyManager.NewKey(tc.serializedKeyFormat)
			if err == nil {
				t.Error("NewKey() err = nil, want not error")
			}

			_, err = keyManager.NewKeyData(tc.serializedKeyFormat)
			if err == nil {
				t.Error("NewKeyData() err = nil, want error")
			}
		})
	}
}

func mustCreateSubtleAEAD(t *testing.T, key []byte, ivSize int, hashAlgo string, macKey []byte, tagSize int) tink.AEAD {
	ctr, err := subtle.NewAESCTR(key, ivSize)
	if err != nil {
		t.Fatalf("subtle.NewAESCTR(key, ivSize) err = %v, want nil", err)
	}

	mac, err := subtleMac.NewHMAC(hashAlgo, macKey, uint32(tagSize))
	if err != nil {
		t.Fatalf("subtleMac.NewHMAC(hashAlgo, macKey, uint32(tagSize)) err = %v, want nil", err)
	}

	cipher, err := subtle.NewEncryptThenAuthenticate(ctr, mac, tagSize)
	if err != nil {
		t.Fatalf("subtle.NewEncryptThenAuthenticate(ctr, mac, tagSize) err = %v, want nil", err)
	}
	return cipher
}

func TestKeyManagerPrimitive(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESCTRHMACAEADTypeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager(%s) err = %v, want nil", testutil.AESCTRHMACAEADTypeURL, err)
	}

	key := &achpb.AesCtrHmacAeadKey{
		Version: 0,
		AesCtrKey: &ctrpb.AesCtrKey{
			Version:  0,
			KeyValue: []byte("0123456789abcdef0123456789abcdef"),
			Params:   &ctrpb.AesCtrParams{IvSize: 16},
		},
		HmacKey: &hmacpb.HmacKey{
			Version:  0,
			KeyValue: []byte("fedba9876543210fedcba9876543210"),
			Params:   &hmacpb.HmacParams{Hash: commonpb.HashType_SHA256, TagSize: 32},
		},
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		t.Fatalf("failed to marshal key: %s", err)
	}

	p, err := keyManager.Primitive(serializedKey)
	if err != nil {
		t.Errorf("Primitive() err = %v, want nil", err)
	}

	aesCTRHMACAEAD, ok := p.(tink.AEAD)
	if !ok {
		t.Errorf("Primitive() returned %T, want tink.AEAD", p)
	}
	other := mustCreateSubtleAEAD(t, key.AesCtrKey.GetKeyValue(), 16, "SHA256", key.HmacKey.GetKeyValue(), 32)
	if err := aeadtestutil.EncryptDecrypt(aesCTRHMACAEAD, other); err != nil {
		t.Errorf("aeadtestutil.EncryptDecrypt(aesCTRHMACAEAD, other) err = %v, want nil", err)
	}
	if err := aeadtestutil.EncryptDecrypt(other, aesCTRHMACAEAD); err != nil {
		t.Errorf("aeadtestutil.EncryptDecrypt(other, aesCTRHMACAEAD) err = %v, want nil", err)
	}
}

func TestKeyManagerPrimitiveWithInvalidKey(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESCTRHMACAEADTypeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager(%s) err = %v, want nil", testutil.AESCTRHMACAEADTypeURL, err)
	}

	emptyKey := &achpb.AesCtrHmacAeadKey{}
	serializedEmptyKey, err := proto.Marshal(emptyKey)
	if err != nil {
		t.Fatalf("failed to marshal key: %s", err)
	}

	keyWithNilKeyParams := &achpb.AesCtrHmacAeadKey{
		Version: 0,
		AesCtrKey: &ctrpb.AesCtrKey{
			Version:  0,
			KeyValue: make([]byte, 32),
			Params:   nil,
		},
		HmacKey: &hmacpb.HmacKey{
			Version:  0,
			KeyValue: make([]byte, 32),
			Params:   nil,
		},
	}
	serializedkeyWithNilKeyParams, err := proto.Marshal(keyWithNilKeyParams)
	if err != nil {
		t.Fatalf("failed to marshal key: %s", err)
	}

	wrongKeyType := &hmacpb.HmacKey{
		Version:  0,
		KeyValue: make([]byte, 32),
		Params:   nil,
	}
	serializedWronKeyType, err := proto.Marshal(wrongKeyType)
	if err != nil {
		t.Fatalf("failed to marshal key: %s", err)
	}

	testcases := []struct {
		name string
		key  []byte
	}{
		{
			name: "nil input",
			key:  nil,
		},
		{
			name: "empty slice",
			key:  []byte{},
		},
		{
			name: "empty key",
			key:  serializedEmptyKey,
		},
		{
			name: "key with nil params",
			key:  serializedkeyWithNilKeyParams,
		},
		{
			name: "wrong key type",
			key:  serializedWronKeyType,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			_, err = keyManager.Primitive(tc.key)
			if err == nil {
				t.Error("Primitive() err = nil, want error")
			}
		})
	}
}
