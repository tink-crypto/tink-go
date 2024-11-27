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

// Package stubconfig provides test utilities that are *NOT* meant for public use.
package stubconfig

import (
	"reflect"

	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/key"
)

// StubConfig simulates the behaviour of the real Config for the purposes of
// testing the key managers registration functions and primitive constructors
// registration functions in the primitive packages (since the primitive packages
// cannot directly depend on the Config to avoid circular dependency).
type StubConfig struct {
	KeyManagers           map[string]registry.KeyManager
	PrimitiveConstructors map[reflect.Type]func(key key.Key) (any, error)
}

// RegisterKeyManager is the method responsible for the KeyManager registration
// in the Config interface.
func (sc *StubConfig) RegisterKeyManager(keyTypeURL string, km registry.KeyManager, _ internalapi.Token) error {
	sc.KeyManagers[keyTypeURL] = km
	return nil
}

// RegisterPrimitiveConstructor is the method responsible for the
// primitive constructor registration in the Config interface.
func (sc *StubConfig) RegisterPrimitiveConstructor(keyType reflect.Type, primitiveConstructor func(key key.Key) (any, error), _ internalapi.Token) error {
	sc.PrimitiveConstructors[keyType] = primitiveConstructor
	return nil
}

// NewStubConfig returns an empty instance of a StubConfig.
func NewStubConfig() *StubConfig {
	return &StubConfig{make(map[string]registry.KeyManager), make(map[reflect.Type]func(key key.Key) (any, error))}
}
