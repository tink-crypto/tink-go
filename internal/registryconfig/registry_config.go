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

// Package registryconfig is a transitioning stepping stone used by the
// keyset handle in cases where a configuration is not provided by the user,
// so it needs to resort to using the old global registry methods.
package registryconfig

import (
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveregistry"
	"github.com/tink-crypto/tink-go/v2/key"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

// RegistryConfig is an internal way for the keyset handle to access the
// old global Registry through the new Configuration interface.
type RegistryConfig struct{}

// PrimitiveFromKeyData constructs a primitive from a [key.Key] using the registry.
func (c *RegistryConfig) PrimitiveFromKeyData(keyData *tinkpb.KeyData, _ internalapi.Token) (any, error) {
	return registry.PrimitiveFromKeyData(keyData)
}

// PrimitiveFromKey constructs a primitive from a [key.Key] using the registry.
func (c *RegistryConfig) PrimitiveFromKey(key key.Key, _ internalapi.Token) (any, error) {
	return primitiveregistry.Primitive(key)
}

// RegisterKeyManager registers a provided [registry.KeyManager] by forwarding
// it directly to the Registry.
func (c *RegistryConfig) RegisterKeyManager(km registry.KeyManager, _ internalapi.Token) error {
	return registry.RegisterKeyManager(km)
}
