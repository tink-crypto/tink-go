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
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	aeadsubtle "github.com/tink-crypto/tink-go/v2/aead/subtle"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/internal/registryconfig"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/testutil"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestPrimitiveFromKey(t *testing.T) {
	keyset, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
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
	if _, ok := p.(*aesgcm.AEAD); !ok {
		t.Errorf("p is not of type *aesgcm.AEAD; got %T", p)
	}
}

func TestPrimitiveFromKeyData(t *testing.T) {
	keyset, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	entry, err := keyset.Entry(0)
	if err != nil {
		t.Fatalf("keyset.Entry() err = %v, want nil", err)
	}
	protoKey, err := protoserialization.SerializeKey(entry.Key())
	if err != nil {
		t.Fatalf("protoserialization.SerializeKey() err = %v, want nil", err)
	}
	registryConfig := &registryconfig.RegistryConfig{}
	p, err := registryConfig.PrimitiveFromKeyData(protoKey.KeyData(), internalapi.Token{})
	if err != nil {
		t.Errorf("registryConfig.PrimitiveFromKey() err = %v, want nil", err)
	}
	if _, ok := p.(*aeadsubtle.AESGCM); !ok {
		t.Error("p is not of type *aeadsubtle.AESGCM")
	}
}

func TestPrimitiveFromKeyErrors(t *testing.T) {
	registryConfig := &registryconfig.RegistryConfig{}
	testCases := []struct {
		name string
		key  key.Key
	}{
		{
			name: "unregistered key type",
			key:  &stubKey{},
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

type stubPrimitive struct{}
type stubKeyManager struct{}

func (km *stubKeyManager) Primitive(_ []byte) (any, error)              { return &stubPrimitive{}, nil }
func (km *stubKeyManager) NewKey(_ []byte) (proto.Message, error)       { return nil, nil }
func (km *stubKeyManager) DoesSupport(typeURL string) bool              { return typeURL == "stubKeyManager" }
func (km *stubKeyManager) TypeURL() string                              { return "stubKeyManager" }
func (km *stubKeyManager) NewKeyData(_ []byte) (*tinkpb.KeyData, error) { return nil, nil }

func TestRegisterKeyManager(t *testing.T) {
	registryConfig := &registryconfig.RegistryConfig{}
	if err := registryConfig.RegisterKeyManager(new(stubKeyManager), internalapi.Token{}); err != nil {
		t.Fatalf("registryConfig.RegisterKeyManager() err = %v, want nil", err)
	}
	if _, err := registry.GetKeyManager("stubKeyManager"); err != nil {
		t.Fatalf("registry.GetKeyManager(\"stubKeyManager\") err = %v, want nil", err)
	}
	primitive, err := registry.Primitive(new(stubKeyManager).TypeURL(), []byte{0, 1, 2, 3})
	if err != nil {
		t.Fatalf("registry.Primitive() err = %v, want nil", err)
	}
	if _, ok := primitive.(*stubPrimitive); !ok {
		t.Error("primitive is not of type *stubPrimitive")
	}
}

type stubKey struct{}

func (k *stubKey) Parameters() key.Parameters    { return nil }
func (k *stubKey) Equal(other key.Key) bool      { return true }
func (k *stubKey) IDRequirement() (uint32, bool) { return 123, true }

// stubPrimitiveConstructor	creates a stubPrimitive from a stubKey.
func stubPrimitiveConstructor(k key.Key) (any, error) {
	_, ok := k.(*stubKey)
	if !ok {
		return nil, fmt.Errorf("key is of type %T; needed *stubKey", k)
	}
	return &stubPrimitive{}, nil
}

// anotherStubPrimitiveConstructor	creates a stubPrimitive from a stubKey.
func anotherStubPrimitiveConstructor(k key.Key) (any, error) {
	return stubPrimitiveConstructor(k)
}

func alwaysFailingStubPrimitiveConstructor(k key.Key) (any, error) {
	return nil, fmt.Errorf("I always fail :(")
}

func TestRegisterPrimitiveConstructor(t *testing.T) {
	defer registryconfig.UnregisterPrimitiveConstructor[*stubKey]()
	if err := registryconfig.RegisterPrimitiveConstructor[*stubKey](stubPrimitiveConstructor); err != nil {
		t.Errorf("registryconfig.RegisterPrimitiveConstructor[*stubKey](stubPrimitiveConstructor) err = %v, want nil", err)
	}
	rc := &registryconfig.RegistryConfig{}
	primitive, err := rc.PrimitiveFromKey(new(stubKey), internalapi.Token{})
	if err != nil {
		t.Fatalf("rc.PrimitiveFromKey() err = %v, want nil", err)
	}
	if _, ok := primitive.(*stubPrimitive); !ok {
		t.Error("primitive is not of type *stubPrimitive")
	}
}

func stubPrimitiveConstructorFromFallbackProtoKey(k key.Key) (any, error) {
	_, ok := k.(*protoserialization.FallbackProtoKey)
	if !ok {
		return nil, fmt.Errorf("key is of type %T; needed *protoserialization.FallbackProtoKey", k)
	}
	return &stubPrimitive{}, nil
}

func TestPrimitiveFromKeyFailsIfCreatorFails(t *testing.T) {
	defer registryconfig.UnregisterPrimitiveConstructor[*stubKey]()
	if err := registryconfig.RegisterPrimitiveConstructor[*stubKey](alwaysFailingStubPrimitiveConstructor); err != nil {
		t.Errorf("registryconfig.RegisterPrimitiveConstructor[*stubKey](alwaysFailingStubPrimitiveConstructor) err = %v, want nil", err)
	}
	rc := &registryconfig.RegistryConfig{}
	if _, err := rc.PrimitiveFromKey(new(stubKey), internalapi.Token{}); err == nil {
		t.Errorf("rc.PrimitiveFromKey() err = nil, want error")
	}
}

func TestRegisterPrimitiveConstructorSucceedsIfDoubleRegister(t *testing.T) {
	defer registryconfig.UnregisterPrimitiveConstructor[*stubKey]()
	if err := registryconfig.RegisterPrimitiveConstructor[*stubKey](stubPrimitiveConstructor); err != nil {
		t.Fatalf("registryconfig.RegisterPrimitiveConstructor[*stubKey](stubPrimitiveConstructor) err = %v, want nil", err)
	}
	if err := registryconfig.RegisterPrimitiveConstructor[*stubKey](stubPrimitiveConstructor); err != nil {
		t.Errorf("registryconfig.RegisterPrimitiveConstructor[*stubKey](stubPrimitiveConstructor) err = %v, want nil", err)
	}
}

func TestRegisterPrimitiveConstructorFailsIfRegisterAnotherCreatorForSameKeyType(t *testing.T) {
	defer registryconfig.UnregisterPrimitiveConstructor[*stubKey]()
	if err := registryconfig.RegisterPrimitiveConstructor[*stubKey](stubPrimitiveConstructor); err != nil {
		t.Fatalf("registryconfig.RegisterPrimitiveConstructor[*stubKey](stubPrimitiveConstructor) err = %v, want nil", err)
	}
	if err := registryconfig.RegisterPrimitiveConstructor[*stubKey](anotherStubPrimitiveConstructor); err == nil {
		t.Errorf("registryconfig.RegisterPrimitiveConstructor[*stubKey](anotherStubPrimitiveConstructor) err = nil, want error")
	}
}
