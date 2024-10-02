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

package configuration_test

import (
	"reflect"
	"testing"

	"github.com/tink-crypto/tink-go/v2/internal/configuration"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/key"
)

type testParameters0 struct{}

func (tp testParameters0) HasIDRequirement() bool { return false }
func (tp testParameters0) Equals(other key.Parameters) bool {
	return false
}

type testKey0 struct{}

func (tk testKey0) Parameters() key.Parameters                { return new(testParameters0) }
func (tk testKey0) IDRequirement() (id uint32, required bool) { return 0, false }
func (tk testKey0) Equals(other key.Key) bool                 { return false }

type testPrimitive0 struct{}

type testParameters1 struct{}

func (tp testParameters1) HasIDRequirement() bool { return false }
func (tp testParameters1) Equals(other key.Parameters) bool {
	return false
}

type testKey1 struct{}

func (tk testKey1) Parameters() key.Parameters                { return new(testParameters1) }
func (tk testKey1) IDRequirement() (id uint32, required bool) { return 0, false }
func (tk testKey1) Equals(other key.Key) bool                 { return false }

type testPrimitive1 struct{}

type testKeyUnregistered struct{}

func (tk testKeyUnregistered) Parameters() key.Parameters                { return new(testParameters1) }
func (tk testKeyUnregistered) IDRequirement() (id uint32, required bool) { return 0, false }
func (tk testKeyUnregistered) Equals(other key.Key) bool                 { return false }

func TestConfigurationWorks(t *testing.T) {
	testConfiguration, err := configuration.New()
	if err != nil {
		t.Fatalf("Configuration.New() err = %v, want nil", err)
	}
	token := internalapi.Token{}

	err = testConfiguration.RegisterPrimitiveConstructor(reflect.TypeFor[testKey0](), func(k key.Key) (any, error) { return testPrimitive0{}, nil }, token)
	if err != nil {
		t.Fatalf("testConfiguration.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}

	p0, err := testConfiguration.PrimitiveFromKey(testKey0{}, token)
	if err != nil {
		t.Fatalf("testConfiguration.PrimitiveFromKey() err = %v, want nil", err)
	}
	if reflect.TypeOf(p0) != reflect.TypeFor[testPrimitive0]() {
		t.Errorf("Wrong primitive returned: got %T, want testPrimitive0", p0)
	}
}

func TestMultiplePrimitiveConstructors(t *testing.T) {
	testConfiguration, err := configuration.New()
	if err != nil {
		t.Fatalf("configuration.New() err = %v, want nil", err)
	}
	token := internalapi.Token{}

	err = testConfiguration.RegisterPrimitiveConstructor(reflect.TypeFor[testKey0](), func(k key.Key) (any, error) { return testPrimitive0{}, nil }, token)
	if err != nil {
		t.Fatalf("testConfiguration.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	err = testConfiguration.RegisterPrimitiveConstructor(reflect.TypeFor[testKey1](), func(k key.Key) (any, error) { return testPrimitive1{}, nil }, token)
	if err != nil {
		t.Fatalf("testConfiguration.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}

	p0, err := testConfiguration.PrimitiveFromKey(testKey0{}, token)
	if err != nil {
		t.Fatalf("testConfiguration.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	if reflect.TypeOf(p0) != reflect.TypeFor[testPrimitive0]() {
		t.Errorf("Wrong primitive returned: got %T, want testPrimitive0", p0)
	}
	p1, err := testConfiguration.PrimitiveFromKey(testKey1{}, token)
	if err != nil {
		t.Fatalf("testConfiguration.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	if reflect.TypeOf(p1) != reflect.TypeFor[testPrimitive1]() {
		t.Errorf("Wrong primitive returned: got %T, want testPrimitive0", p1)
	}
}

func TestRegisterDifferentPrimitiveConstructor(t *testing.T) {
	testConfiguration, err := configuration.New()
	if err != nil {
		t.Fatalf("configuration.New() err = %v, want nil", err)
	}
	token := internalapi.Token{}

	err = testConfiguration.RegisterPrimitiveConstructor(reflect.TypeFor[testKey1](), func(k key.Key) (any, error) { return testPrimitive1{}, nil }, token)
	if err != nil {
		t.Fatalf("testConfiguration.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}

	// Register another primitiveCreator for the same key type fails.
	err = testConfiguration.RegisterPrimitiveConstructor(reflect.TypeFor[testKey1](), func(k key.Key) (any, error) { return testPrimitive0{}, nil }, token)
	if err == nil {
		t.Errorf("testConfiguration.RegisterPrimitiveConstructor() err = nil, want error")
	}
}

func TestUnregisteredPrimitive(t *testing.T) {
	testConfiguration, err := configuration.New()
	if err != nil {
		t.Fatalf("configuration.New() err = %v, want nil", err)
	}
	token := internalapi.Token{}

	err = testConfiguration.RegisterPrimitiveConstructor(reflect.TypeFor[testKey0](), func(k key.Key) (any, error) { return testPrimitive0{}, nil }, token)
	if err != nil {
		t.Fatalf("testConfiguration.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}

	res, err := testConfiguration.PrimitiveFromKey(testKeyUnregistered{}, token)
	if res != nil {
		t.Errorf("testConfiguration.PrimitiveFromKey() return value = %v, want nil", res)
	}
	if err == nil {
		t.Errorf("testConfiguration.PrimitiveFromKey() err = nil, want error")
	}
}
