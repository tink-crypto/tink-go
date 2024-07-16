// Copyright 2023 Google LLC
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

package registryconfig_test

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/internal/registryconfig"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac"
	"github.com/tink-crypto/tink-go/v2/mac/subtle"
	"github.com/tink-crypto/tink-go/v2/testutil"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestPrimitiveFromKeyData(t *testing.T) {
	keyData := testutil.NewHMACKeyData(commonpb.HashType_SHA256, 16)
	registryConfig := &registryconfig.RegistryConfig{}
	p, err := registryConfig.PrimitiveFromKeyData(keyData, internalapi.Token{})
	if err != nil {
		t.Errorf("registryConfig.PrimitiveFromKeyData() err = %v, want nil", err)
	}
	if _, ok := p.(*subtle.HMAC); !ok {
		t.Error("primitive is not of type *subtle.HMAC")
	}
}

func TestPrimitiveFromKeyDataErrors(t *testing.T) {
	registryConfig := &registryconfig.RegistryConfig{}

	testCases := []struct {
		name    string
		keyData *tinkpb.KeyData
	}{
		{
			name: "unregistered url",
			keyData: func() *tinkpb.KeyData {
				kd := testutil.NewHMACKeyData(commonpb.HashType_SHA256, 16)
				kd.TypeUrl = "some url"
				return kd
			}(),
		},
		{
			name: "mismatching url",
			keyData: func() *tinkpb.KeyData {
				kd := testutil.NewHMACKeyData(commonpb.HashType_SHA256, 16)
				kd.TypeUrl = testutil.AESGCMTypeURL
				return kd
			}(),
		},
		{
			name:    "nil KeyData",
			keyData: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := registryConfig.PrimitiveFromKeyData(tc.keyData, internalapi.Token{}); err == nil {
				t.Errorf("registryConfig.Primitive() err = nil, want not-nil")
			}
		})
	}
}

func TestPrimitiveFromKey(t *testing.T) {
	keyset, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	entry, err := keyset.Entry(0)
	if err != nil {
		t.Fatalf("keyset.Entry() err = %v, want nil", err)
	}

	registryConfig := &registryconfig.RegistryConfig{}
	p, err := registryConfig.PrimitiveFromKey(entry.Key(), internalapi.Token{})
	if err != nil {
		t.Errorf("registryConfig.PrimitiveFromKey() err = %v, want nil", err)
	}
	if _, ok := p.(*subtle.HMAC); !ok {
		t.Error("p is not of type *subtle.HMAC")
	}
}

func TestPrimitiveFromKeyErrors(t *testing.T) {
	registryConfig := &registryconfig.RegistryConfig{}

	testCases := []struct {
		name string
		key  key.Key
	}{
		{
			name: "unregistered url",
			key: func() key.Key {
				key := testutil.NewHMACKeyData(commonpb.HashType_SHA256, 16)
				key.TypeUrl = "some-unregistered-url"
				return protoserialization.NewFallbackProtoKey(&tinkpb.Keyset_Key{
					KeyData:          key,
					Status:           tinkpb.KeyStatusType_ENABLED,
					KeyId:            1,
					OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				})
			}(),
		},
		{
			name: "mismatching url",
			key: func() key.Key {
				key := testutil.NewHMACKeyData(commonpb.HashType_SHA256, 16)
				key.TypeUrl = testutil.AESGCMTypeURL
				return protoserialization.NewFallbackProtoKey(&tinkpb.Keyset_Key{
					KeyData:          key,
					Status:           tinkpb.KeyStatusType_ENABLED,
					KeyId:            1,
					OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				})
			}(),
		},
		{
			name: "nil key",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := registryConfig.PrimitiveFromKey(tc.key, internalapi.Token{}); err == nil {
				t.Errorf("registryConfig.PrimitiveFromKey() err = nil, want error")
			}
		})
	}
}

type testPrimitive struct{}
type testKeyManager struct{}

func (km *testKeyManager) Primitive(_ []byte) (any, error)              { return &testPrimitive{}, nil }
func (km *testKeyManager) NewKey(_ []byte) (proto.Message, error)       { return nil, nil }
func (km *testKeyManager) DoesSupport(typeURL string) bool              { return typeURL == "testKeyManager" }
func (km *testKeyManager) TypeURL() string                              { return "testKeyManager" }
func (km *testKeyManager) NewKeyData(_ []byte) (*tinkpb.KeyData, error) { return nil, nil }

func TestRegisterKeyManager(t *testing.T) {
	registryConfig := &registryconfig.RegistryConfig{}
	if err := registryConfig.RegisterKeyManager(new(testKeyManager), internalapi.Token{}); err != nil {
		t.Fatalf("registryConfig.RegisterKeyManager() err = %v, want nil", err)
	}
	if _, err := registry.GetKeyManager("testKeyManager"); err != nil {
		t.Fatalf("registry.GetKeyManager(\"testKeyManager\") err = %v, want nil", err)
	}
	primitive, err := registry.Primitive(new(testKeyManager).TypeURL(), []byte{0, 1, 2, 3})
	if err != nil {
		t.Fatalf("registry.Primitive() err = %v, want nil", err)
	}
	if _, ok := primitive.(*testPrimitive); !ok {
		t.Error("primitive is not of type *testPrimitive")
	}
}
