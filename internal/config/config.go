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

// Package config provides internal implementation of Configs.
package config

import (
	"fmt"
	"reflect"

	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/key"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

// Config keeps a collection of functions that create a primitive from
// [key.Key].
//
// This is an internal API.
type Config struct {
	primitiveConstructors map[reflect.Type]primitiveConstructor
	keysetManagers        map[string]registry.KeyManager
}

type primitiveConstructor func(key key.Key) (any, error)

// PrimitiveFromKeyData creates a primitive from the given [tinkpb.KeyData].
// Returns an error if there is no key manager registered for the given key
// type URL.
//
// This is an internal API.
func (c *Config) PrimitiveFromKeyData(kd *tinkpb.KeyData, _ internalapi.Token) (any, error) {
	km, ok := c.keysetManagers[kd.GetTypeUrl()]
	if !ok {
		return nil, fmt.Errorf("PrimitiveFromKeyData: no key manager for key URL %v", kd.GetTypeUrl())
	}
	return km.Primitive(kd.GetValue())
}

// PrimitiveFromKey creates a primitive from the given [key.Key]. Returns an
// error if there is no primitiveConstructor registered for the given key.
//
// This is an internal API.
func (c *Config) PrimitiveFromKey(k key.Key, _ internalapi.Token) (any, error) {
	keyType := reflect.TypeOf(k)
	creator, ok := c.primitiveConstructors[keyType]
	if !ok {
		return nil, fmt.Errorf("PrimitiveFromKey: no primitive creator from key %v registered", keyType)
	}
	return creator(k)
}

// RegisterPrimitiveConstructor registers a primitiveConstructor for the keyType.
// Not thread-safe.
//
// Returns an error if a primitiveConstructor for the keyType already
// registered (no matter whether it's the same object or different, since
// constructors are of type [Func] and they are never considered equal in Go
// unless they are nil).
//
// This is an internal API.
func (c *Config) RegisterPrimitiveConstructor(keyType reflect.Type, constructor primitiveConstructor, _ internalapi.Token) error {
	if _, ok := c.primitiveConstructors[keyType]; ok {
		return fmt.Errorf("RegisterPrimitiveConstructor: attempt to register a different primitive constructor for the same key type %v", keyType)
	}
	c.primitiveConstructors[keyType] = constructor
	return nil
}

// RegisterKeyManger registers a key manager for a key type URL.
//
// Not thread-safe.
//
// This is an internal API.
func (c *Config) RegisterKeyManger(keyTypeURL string, km registry.KeyManager, _ internalapi.Token) error {
	if _, ok := c.keysetManagers[keyTypeURL]; ok {
		return fmt.Errorf("RegisterKeyManger: attempt to register a different key manager for %v", keyTypeURL)
	}
	c.keysetManagers[keyTypeURL] = km
	return nil
}

// New creates an empty Config.
func New() (*Config, error) {
	return &Config{
		primitiveConstructors: map[reflect.Type]primitiveConstructor{},
		keysetManagers:        map[string]registry.KeyManager{},
	}, nil
}
