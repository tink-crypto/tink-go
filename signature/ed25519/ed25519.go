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

// Package ed25519 provides ED25519 keys and parameters definitions, and key
// managers.
package ed25519

import (
	"fmt"

	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/internalregistry"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/internal/registryconfig"
)

func init() {
	if err := registry.RegisterKeyManager(new(signerKeyManager)); err != nil {
		panic(fmt.Sprintf("ed25519.init() failed: %v", err))
	}
	if err := internalregistry.AllowKeyDerivation(signerTypeURL); err != nil {
		panic(fmt.Sprintf("ed25519.init() failed: %v", err))
	}
	if err := registry.RegisterKeyManager(new(verifierKeyManager)); err != nil {
		panic(fmt.Sprintf("ed25519.init() failed: %v", err))
	}
	if err := protoserialization.RegisterKeySerializer[*PublicKey](&publicKeySerializer{}); err != nil {
		panic(fmt.Sprintf("ed25519.init() failed: %v", err))
	}
	if err := protoserialization.RegisterKeyParser(verifierTypeURL, &publicKeyParser{}); err != nil {
		panic(fmt.Sprintf("ed25519.init() failed: %v", err))
	}
	if err := protoserialization.RegisterKeySerializer[*PrivateKey](&privateKeySerializer{}); err != nil {
		panic(fmt.Sprintf("ed25519.init() failed: %v", err))
	}
	if err := protoserialization.RegisterKeyParser(signerTypeURL, &privateKeyParser{}); err != nil {
		panic(fmt.Sprintf("ed25519.init() failed: %v", err))
	}
	if err := protoserialization.RegisterParametersSerializer[*Parameters](&parametersSerializer{}); err != nil {
		panic(fmt.Sprintf("ed25519.init() failed: %v", err))
	}
	if err := protoserialization.RegisterParametersParser(signerTypeURL, &parametersParser{}); err != nil {
		panic(fmt.Sprintf("ed25519.init() failed: %v", err))
	}
	if err := registryconfig.RegisterPrimitiveConstructor[*PublicKey](verifierConstructor); err != nil {
		panic(fmt.Sprintf("ed25519.init() failed: %v", err))
	}
	if err := registryconfig.RegisterPrimitiveConstructor[*PrivateKey](signerConstructor); err != nil {
		panic(fmt.Sprintf("ed25519.init() failed: %v", err))
	}
}
