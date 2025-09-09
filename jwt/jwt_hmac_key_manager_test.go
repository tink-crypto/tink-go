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

package jwt

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	jwtmacpb "github.com/tink-crypto/tink-go/v2/proto/jwt_hmac_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

type jwtKeyManagerTestCase struct {
	tag       string
	keyFormat *jwtmacpb.JwtHmacKeyFormat
	key       *jwtmacpb.JwtHmacKey
}

const (
	typeURL = "type.googleapis.com/google.crypto.tink.JwtHmacKey"
)

func generateKeyFormat(keySize uint32, algorithm jwtmacpb.JwtHmacAlgorithm) *jwtmacpb.JwtHmacKeyFormat {
	return &jwtmacpb.JwtHmacKeyFormat{
		KeySize:   keySize,
		Algorithm: algorithm,
	}
}

func TestDoesSupport(t *testing.T) {
	km, err := registry.GetKeyManager(typeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager(%q) error = %v, want nil", typeURL, err)
	}
	if !km.DoesSupport(typeURL) {
		t.Errorf("km.DoesSupport(%q) = false, want true", typeURL)
	}
}

func TestTypeURL(t *testing.T) {
	km, err := registry.GetKeyManager(typeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager(%q) error = %v, want nil", typeURL, err)
	}
	if km.TypeURL() != typeURL {
		t.Errorf("km.TypeURL() = %q, want %q", km.TypeURL(), typeURL)
	}
}

var invalidKeyFormatTestCases = []jwtKeyManagerTestCase{
	{
		tag:       "invalid hash algorithm",
		keyFormat: generateKeyFormat(32, jwtmacpb.JwtHmacAlgorithm_HS_UNKNOWN),
	},
	{
		tag:       "invalid HS256 key size",
		keyFormat: generateKeyFormat(31, jwtmacpb.JwtHmacAlgorithm_HS256),
	},
	{
		tag:       "invalid HS384 key size",
		keyFormat: generateKeyFormat(47, jwtmacpb.JwtHmacAlgorithm_HS384),
	},
	{
		tag:       "invalid HS512 key size",
		keyFormat: generateKeyFormat(63, jwtmacpb.JwtHmacAlgorithm_HS512),
	},
	{
		tag:       "empty key format",
		keyFormat: &jwtmacpb.JwtHmacKeyFormat{},
	},
	{
		tag:       "nil key format",
		keyFormat: nil,
	},
}

func TestNewKeyInvalidFormatFails(t *testing.T) {
	for _, tc := range invalidKeyFormatTestCases {
		t.Run(tc.tag, func(t *testing.T) {
			km, err := registry.GetKeyManager(typeURL)
			if err != nil {
				t.Errorf("registry.GetKeyManager(%q): %v", typeURL, err)
			}
			serializedKeyFormat, err := proto.Marshal(tc.keyFormat)
			if err != nil {
				t.Errorf("serializing key format: %v", err)
			}
			if _, err := km.NewKey(serializedKeyFormat); err == nil {
				t.Errorf("km.NewKey() err = nil, want error")
			}
		})
	}
}

func TestNewDataInvalidFormatFails(t *testing.T) {
	for _, tc := range invalidKeyFormatTestCases {
		t.Run(tc.tag, func(t *testing.T) {
			km, err := registry.GetKeyManager(typeURL)
			if err != nil {
				t.Errorf("registry.GetKeyManager(%q): %v", typeURL, err)
			}
			serializedKeyFormat, err := proto.Marshal(tc.keyFormat)
			if err != nil {
				t.Errorf("serializing key format: %v", err)
			}
			if _, err := km.NewKeyData(serializedKeyFormat); err == nil {
				t.Errorf("km.NewKey() err = nil, want error")
			}
		})
	}
}

var validKeyFormatTestCases = []jwtKeyManagerTestCase{
	{
		tag:       "SHA256 hash algorithm",
		keyFormat: generateKeyFormat(32, jwtmacpb.JwtHmacAlgorithm_HS256),
	},
	{
		tag:       "SHA384 hash algorithm",
		keyFormat: generateKeyFormat(48, jwtmacpb.JwtHmacAlgorithm_HS384),
	},
	{
		tag:       "SHA512 hash algorithm",
		keyFormat: generateKeyFormat(64, jwtmacpb.JwtHmacAlgorithm_HS512),
	},
}

func TestNewKey(t *testing.T) {
	for _, tc := range validKeyFormatTestCases {
		t.Run(tc.tag, func(t *testing.T) {
			km, err := registry.GetKeyManager(typeURL)
			if err != nil {
				t.Errorf("registry.GetKeyManager(%q): %v", typeURL, err)
			}
			serializedKeyFormat, err := proto.Marshal(tc.keyFormat)
			if err != nil {
				t.Errorf("serializing key format: %v", err)
			}
			k, err := km.NewKey(serializedKeyFormat)
			if err != nil {
				t.Errorf("km.NewKey() err = %v, want nil", err)
			}
			key, ok := k.(*jwtmacpb.JwtHmacKey)
			if !ok {
				t.Errorf("key isn't of type JwtHmacKey")
			}
			if key.Algorithm != tc.keyFormat.Algorithm {
				t.Errorf("k.Algorithm = %v, want %v", key.Algorithm, tc.keyFormat.Algorithm)
			}
			if len(key.KeyValue) != int(tc.keyFormat.KeySize) {
				t.Errorf("len(key.KeyValue) = %d, want %d", len(key.KeyValue), tc.keyFormat.KeySize)
			}
		})
	}
}

func TestNewKeyData(t *testing.T) {
	for _, tc := range validKeyFormatTestCases {
		t.Run(tc.tag, func(t *testing.T) {
			km, err := registry.GetKeyManager(typeURL)
			if err != nil {
				t.Errorf("registry.GetKeyManager(%q): %v", typeURL, err)
			}
			serializedKeyFormat, err := proto.Marshal(tc.keyFormat)
			if err != nil {
				t.Errorf("serializing key format: %v", err)
			}
			k, err := km.NewKeyData(serializedKeyFormat)
			if err != nil {
				t.Errorf("km.NewKeyData() err = %v, want nil", err)
			}
			if k.GetTypeUrl() != typeURL {
				t.Errorf("k.GetTypeUrl() = %q, want %q", k.GetTypeUrl(), typeURL)
			}
			if k.GetKeyMaterialType() != tinkpb.KeyData_SYMMETRIC {
				t.Errorf("k.GetKeyMaterialType() = %q, want %q", k.GetKeyMaterialType(), tinkpb.KeyData_SYMMETRIC)
			}
		})
	}
}

func generateKey(keySize, version uint32, algorithm jwtmacpb.JwtHmacAlgorithm, kid *jwtmacpb.JwtHmacKey_CustomKid) *jwtmacpb.JwtHmacKey {
	return &jwtmacpb.JwtHmacKey{
		KeyValue:  random.GetRandomBytes(keySize),
		Algorithm: algorithm,
		CustomKid: kid,
		Version:   version,
	}
}

func TestKeyManagerPrimitiveAlwaysFails(t *testing.T) {
	km, err := registry.GetKeyManager(typeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q): %v", typeURL, err)
	}
	serializedKey, err := proto.Marshal(generateKey(32, 0, jwtmacpb.JwtHmacAlgorithm_HS256, nil))
	if err != nil {
		t.Fatalf("serializing key format: %v", err)
	}
	if _, err := km.Primitive(serializedKey); err == nil {
		t.Errorf("km.Primitive() err = nil, want error")
	}
}

func TestGeneratesDifferentKeys(t *testing.T) {
	km, err := registry.GetKeyManager(typeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager(%q): %v", typeURL, err)
	}
	serializedKeyFormat, err := proto.Marshal(generateKeyFormat(32, jwtmacpb.JwtHmacAlgorithm_HS256))
	if err != nil {
		t.Errorf("serializing key format: %v", err)
	}
	k1, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		t.Errorf("km.NewKey() err = %v, want nil", err)
	}
	k2, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		t.Errorf("km.NewKey() err = %v, want nil", err)
	}
	key1, ok := k1.(*jwtmacpb.JwtHmacKey)
	if !ok {
		t.Errorf("k1 isn't of type JwtHmacKey")
	}
	key2, ok := k2.(*jwtmacpb.JwtHmacKey)
	if !ok {
		t.Errorf("k2 isn't of type JwtHmacKey")
	}
	if cmp.Equal(key1.GetKeyValue(), key2.GetKeyValue()) {
		t.Errorf("key material should differ")
	}
}
