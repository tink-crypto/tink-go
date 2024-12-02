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

package config_test

import (
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/internal/config"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/key"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

type testParameters0 struct{}

func (tp testParameters0) HasIDRequirement() bool { return false }
func (tp testParameters0) Equal(other key.Parameters) bool {
	return false
}

type testKey0 struct{}

func (tk testKey0) Parameters() key.Parameters                { return new(testParameters0) }
func (tk testKey0) IDRequirement() (id uint32, required bool) { return 0, false }
func (tk testKey0) Equal(other key.Key) bool                  { return false }

type testPrimitive0 struct{}

type testParameters1 struct{}

func (tp testParameters1) HasIDRequirement() bool { return false }
func (tp testParameters1) Equal(other key.Parameters) bool {
	return false
}

type testKey1 struct{}

func (tk testKey1) Parameters() key.Parameters                { return new(testParameters1) }
func (tk testKey1) IDRequirement() (id uint32, required bool) { return 0, false }
func (tk testKey1) Equal(other key.Key) bool                  { return false }

type testPrimitive1 struct{}

type testKeyUnregistered struct{}

func (tk testKeyUnregistered) Parameters() key.Parameters                { return new(testParameters1) }
func (tk testKeyUnregistered) IDRequirement() (id uint32, required bool) { return 0, false }
func (tk testKeyUnregistered) Equal(other key.Key) bool                  { return false }

func TestConfigPrimitiveFromKeyWorks(t *testing.T) {
	testConfig, err := config.New()
	if err != nil {
		t.Fatalf("Config.New() err = %v, want nil", err)
	}
	token := internalapi.Token{}

	err = testConfig.RegisterPrimitiveConstructor(reflect.TypeFor[testKey0](), func(k key.Key) (any, error) { return testPrimitive0{}, nil }, token)
	if err != nil {
		t.Fatalf("testConfig.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}

	p0, err := testConfig.PrimitiveFromKey(testKey0{}, token)
	if err != nil {
		t.Fatalf("testConfig.PrimitiveFromKey() err = %v, want nil", err)
	}
	if reflect.TypeOf(p0) != reflect.TypeFor[testPrimitive0]() {
		t.Errorf("Wrong primitive returned: got %T, want testPrimitive0", p0)
	}
}

const (
	typeURL0 = "type_url_0"
	typeURL1 = "type_url_1"
)

type stubKeyManager0 struct{}

func (km *stubKeyManager0) Primitive(_ []byte) (any, error)              { return &testPrimitive0{}, nil }
func (km *stubKeyManager0) NewKeyData(_ []byte) (*tinkpb.KeyData, error) { return nil, nil }
func (km *stubKeyManager0) DoesSupport(t string) bool                    { return t == typeURL0 }
func (km *stubKeyManager0) TypeURL() string                              { return typeURL0 }
func (km *stubKeyManager0) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, nil
}

type stubKeyManager1 struct{}

func (km *stubKeyManager1) Primitive(_ []byte) (any, error)                          { return &testPrimitive1{}, nil }
func (km *stubKeyManager1) NewKeyData(_ []byte) (*tinkpb.KeyData, error)             { return nil, nil }
func (km *stubKeyManager1) DoesSupport(t string) bool                                { return t == typeURL1 }
func (km *stubKeyManager1) TypeURL() string                                          { return typeURL1 }
func (km *stubKeyManager1) NewKey(serializedKeyFormat []byte) (proto.Message, error) { return nil, nil }

func TestConfigPrimitiveFromKeDataWorks(t *testing.T) {
	testConfig, err := config.New()
	if err != nil {
		t.Fatalf("Config.New() err = %v, want nil", err)
	}
	token := internalapi.Token{}

	err = testConfig.RegisterKeyManager(typeURL0, &stubKeyManager0{}, token)
	if err != nil {
		t.Fatalf("testConfig.RegisterKeyManager() err = %v, want nil", err)
	}

	keyData := &tinkpb.KeyData{
		TypeUrl: typeURL0,
		Value:   []byte("key"),
	}
	p0, err := testConfig.PrimitiveFromKeyData(keyData, token)
	if err != nil {
		t.Fatalf("testConfig.PrimitiveFromKeyData() err = %v, want nil", err)
	}
	if p0.(*testPrimitive0) == nil {
		t.Errorf("Wrong primitive returned: got %T, want testPrimitive0", p0)
	}
}

func TestMultiplePrimitiveConstructors(t *testing.T) {
	testConfig, err := config.New()
	if err != nil {
		t.Fatalf("config.New() err = %v, want nil", err)
	}
	token := internalapi.Token{}

	err = testConfig.RegisterPrimitiveConstructor(reflect.TypeFor[testKey0](), func(k key.Key) (any, error) { return testPrimitive0{}, nil }, token)
	if err != nil {
		t.Fatalf("testConfig.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	err = testConfig.RegisterPrimitiveConstructor(reflect.TypeFor[testKey1](), func(k key.Key) (any, error) { return testPrimitive1{}, nil }, token)
	if err != nil {
		t.Fatalf("testConfig.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}

	p0, err := testConfig.PrimitiveFromKey(testKey0{}, token)
	if err != nil {
		t.Fatalf("testConfig.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	if reflect.TypeOf(p0) != reflect.TypeFor[testPrimitive0]() {
		t.Errorf("Wrong primitive returned: got %T, want testPrimitive0", p0)
	}
	p1, err := testConfig.PrimitiveFromKey(testKey1{}, token)
	if err != nil {
		t.Fatalf("testConfig.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	if reflect.TypeOf(p1) != reflect.TypeFor[testPrimitive1]() {
		t.Errorf("Wrong primitive returned: got %T, want testPrimitive0", p1)
	}
}

func TestMultipleKeyManagers(t *testing.T) {
	testConfig, err := config.New()
	if err != nil {
		t.Fatalf("config.New() err = %v, want nil", err)
	}
	token := internalapi.Token{}

	err = testConfig.RegisterKeyManager(typeURL0, &stubKeyManager0{}, token)
	if err != nil {
		t.Fatalf("testConfig.RegisterKeyManager() err = %v, want nil", err)
	}
	err = testConfig.RegisterKeyManager(typeURL1, &stubKeyManager1{}, token)
	if err != nil {
		t.Fatalf("testConfig.RegisterKeyManager() err = %v, want nil", err)
	}

	p0, err := testConfig.PrimitiveFromKeyData(&tinkpb.KeyData{TypeUrl: typeURL0, Value: []byte("key")}, token)
	if err != nil {
		t.Fatalf("testConfig.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	if p0.(*testPrimitive0) == nil {
		t.Errorf("Wrong primitive returned: got %T, want testPrimitive0", p0)
	}
	p1, err := testConfig.PrimitiveFromKeyData(&tinkpb.KeyData{TypeUrl: typeURL1, Value: []byte("key")}, token)
	if err != nil {
		t.Fatalf("testConfig.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	if p1.(*testPrimitive1) == nil {
		t.Errorf("Wrong primitive returned: got %T, want testPrimitive0", p1)
	}
}

func TestRegisterDifferentPrimitiveConstructor(t *testing.T) {
	testConfig, err := config.New()
	if err != nil {
		t.Fatalf("config.New() err = %v, want nil", err)
	}
	token := internalapi.Token{}

	err = testConfig.RegisterPrimitiveConstructor(reflect.TypeFor[testKey1](), func(k key.Key) (any, error) { return testPrimitive1{}, nil }, token)
	if err != nil {
		t.Fatalf("testConfig.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}

	// Register another primitiveCreator for the same key type fails.
	err = testConfig.RegisterPrimitiveConstructor(reflect.TypeFor[testKey1](), func(k key.Key) (any, error) { return testPrimitive0{}, nil }, token)
	if err == nil {
		t.Errorf("testConfig.RegisterPrimitiveConstructor() err = nil, want error")
	}
}

func TestRegisterDifferentKeyManagers(t *testing.T) {
	testConfig, err := config.New()
	if err != nil {
		t.Fatalf("config.New() err = %v, want nil", err)
	}
	token := internalapi.Token{}

	err = testConfig.RegisterKeyManager(typeURL0, &stubKeyManager0{}, token)
	if err != nil {
		t.Fatalf("testConfig.RegisterKeyManager() err = %v, want nil", err)
	}

	// Register another primitiveCreator for the same key type fails.
	if err = testConfig.RegisterKeyManager(typeURL0, &stubKeyManager1{}, token); err == nil {
		t.Errorf("testConfig.RegisterKeyManager() err = nil, want error")
	}
}

func TestUnregisteredPrimitive(t *testing.T) {
	testConfig, err := config.New()
	if err != nil {
		t.Fatalf("config.New() err = %v, want nil", err)
	}
	token := internalapi.Token{}

	err = testConfig.RegisterPrimitiveConstructor(reflect.TypeFor[testKey0](), func(k key.Key) (any, error) { return testPrimitive0{}, nil }, token)
	if err != nil {
		t.Fatalf("testConfig.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}

	res, err := testConfig.PrimitiveFromKey(testKeyUnregistered{}, token)
	if res != nil {
		t.Errorf("testConfig.PrimitiveFromKey() return value = %v, want nil", res)
	}
	if err == nil {
		t.Errorf("testConfig.PrimitiveFromKey() err = nil, want error")
	}
}

func TestUnregisteredKeyManager(t *testing.T) {
	testConfig, err := config.New()
	if err != nil {
		t.Fatalf("config.New() err = %v, want nil", err)
	}
	token := internalapi.Token{}

	if err = testConfig.RegisterKeyManager(typeURL0, &stubKeyManager0{}, token); err != nil {
		t.Fatalf("testConfig.RegisterKeyManager() err = %v, want nil", err)
	}

	if _, err := testConfig.PrimitiveFromKeyData(&tinkpb.KeyData{TypeUrl: typeURL1, Value: []byte("key")}, token); err == nil {
		t.Errorf("testConfig.PrimitiveFromKey() err = nil, want error")
	}
}
