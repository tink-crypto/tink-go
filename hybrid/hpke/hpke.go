// Copyright 2025 Google LLC
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

// Package hpke contains HPKE (Hybrid Public Key Encryption) key managers.
package hpke

import (
	"fmt"

	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/internal/registryconfig"
)

func init() {
	if err := registry.RegisterKeyManager(new(publicKeyManager)); err != nil {
		panic(fmt.Sprintf("hpke.init() failed: %v", err))
	}
	if err := registry.RegisterKeyManager(new(privateKeyManager)); err != nil {
		panic(fmt.Sprintf("hpke.init() failed: %v", err))
	}
	if err := protoserialization.RegisterKeySerializer[*PublicKey](&publicKeySerializer{}); err != nil {
		panic(fmt.Sprintf("hpke.init() failed: %v", err))
	}
	if err := protoserialization.RegisterKeyParser(publicKeyTypeURL, &publicKeyParser{}); err != nil {
		panic(fmt.Sprintf("hpke.init() failed: %v", err))
	}
	if err := protoserialization.RegisterKeySerializer[*PrivateKey](&privateKeySerializer{}); err != nil {
		panic(fmt.Sprintf("hpke.init() failed: %v", err))
	}
	if err := protoserialization.RegisterKeyParser(privateKeyTypeURL, &privateKeyParser{}); err != nil {
		panic(fmt.Sprintf("hpke.init() failed: %v", err))
	}
	if err := protoserialization.RegisterParametersSerializer[*Parameters](&parametersSerializer{}); err != nil {
		panic(fmt.Sprintf("hpke.init() failed: %v", err))
	}
	if err := protoserialization.RegisterParametersParser(privateKeyTypeURL, &parametersParser{}); err != nil {
		panic(fmt.Sprintf("hpke.init() failed: %v", err))
	}
	if err := registryconfig.RegisterPrimitiveConstructor[*PublicKey](hybridEncryptConstructor); err != nil {
		panic(fmt.Sprintf("hpke.init() failed: %v", err))
	}
	if err := registryconfig.RegisterPrimitiveConstructor[*PrivateKey](hybridDecryptConstructor); err != nil {
		panic(fmt.Sprintf("hpke.init() failed: %v", err))
	}
}
