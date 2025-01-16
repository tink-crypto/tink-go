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

// Package keygenconfig provides internal implementation of keygen configs.
package keygenconfig

import (
	"fmt"
	"reflect"

	"github.com/tink-crypto/tink-go/v2/key"
)

// Config keeps a collection of functions that create keys from
// [key.Primitive].
type Config struct {
	keyCreators map[reflect.Type]func(p key.Parameters, idRequirement uint32) (key.Key, error)
}

// New creates an empty [Config].
func New() *Config {
	return &Config{
		keyCreators: map[reflect.Type]func(p key.Parameters, idRequirement uint32) (key.Key, error){},
	}
}

// RegisterKeyCreator registers a function that creates a key from
// the given [key.Parameters].
// Not thread-safe.
//
// Returns an error if a creator for parametersType is already registered (no
// matter whether it's the same object or different, since constructors are of
// type [Func] and they are never considered equal in Go unless they are nil).
//
// This is an internal API.
func (c *Config) RegisterKeyCreator(parametersType reflect.Type, creator func(p key.Parameters, idRequirement uint32) (key.Key, error)) error {
	if _, found := c.keyCreators[parametersType]; found {
		return fmt.Errorf("a different key creator already registered for %v", parametersType)
	}
	c.keyCreators[parametersType] = creator
	return nil
}

// CreateKey creates a key from the given [key.Parameters] using the registry.
//
// Not thread-safe.
//
// This is an internal API.
func (c *Config) CreateKey(p key.Parameters, idRequirement uint32) (key.Key, error) {
	creator, found := c.keyCreators[reflect.TypeOf(p)]
	if !found {
		return nil, fmt.Errorf("no creator found for parameters %T", p)
	}
	return creator(p, idRequirement)
}
