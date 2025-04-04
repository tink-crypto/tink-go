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

// Package aesctrhmac provides a key manager for the AES-CTR-HMAC AEAD.
package aesctrhmac

import (
	"fmt"
	"reflect"

	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/internal/registryconfig"
	"github.com/tink-crypto/tink-go/v2/key"
)

type config interface {
	RegisterPrimitiveConstructor(keyType reflect.Type, primitiveConstructor func(key key.Key) (any, error), t internalapi.Token) error
	RegisterKeyManager(keyTypeURL string, km registry.KeyManager, t internalapi.Token) error
}

// RegisterKeyManager registers an instance of an AES-CTR-HMAC AEAD KeyManager
// to the config object provided as the first argument.
//
// It is *NOT* part of the public API.
func RegisterKeyManager(c config, t internalapi.Token) error {
	return c.RegisterKeyManager(typeURL, new(keyManager), t)
}

// RegisterPrimitiveConstructor accepts a config object and registers the
// AES-CTR-HMAC AEAD primitive constructor to the provided config.
//
// It is *NOT* part of the public API.
func RegisterPrimitiveConstructor(c config, t internalapi.Token) error {
	return c.RegisterPrimitiveConstructor(reflect.TypeFor[*Key](), primitiveConstructor, t)
}

func init() {
	if err := registry.RegisterKeyManager(new(keyManager)); err != nil {
		panic(fmt.Sprintf("aesctrhmac.init() failed: %v", err))
	}
	if err := protoserialization.RegisterKeySerializer[*Key](&keySerializer{}); err != nil {
		panic(fmt.Sprintf("aesctrhmac.init() failed: %v", err))
	}
	if err := protoserialization.RegisterKeyParser(typeURL, &keyParser{}); err != nil {
		panic(fmt.Sprintf("aesctrhmac.init() failed: %v", err))
	}
	if err := protoserialization.RegisterParametersSerializer[*Parameters](&parametersSerializer{}); err != nil {
		panic(fmt.Sprintf("aesctrhmac.init() failed: %v", err))
	}
	if err := protoserialization.RegisterParametersParser(typeURL, &parametersParser{}); err != nil {
		panic(fmt.Sprintf("aesctrhmac.init() failed: %v", err))
	}
	if err := registryconfig.RegisterPrimitiveConstructor[*Key](primitiveConstructor); err != nil {
		panic(fmt.Sprintf("aesctrhmac.init() failed: %v", err))
	}
}
