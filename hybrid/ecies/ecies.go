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

// Package ecies contains parameters and keys for ECIES keys with HKDF and AEAD
// encryption.
//
// This follows loosely ECIES ISO 18033-2 (Elliptic Curve Integrated Encryption
// Scheme, see http://www.shoup.net/iso/std6.pdf), with some notable
// differences:
//
//   - use of HKDF key derivation function (instead of KDF1 and KDF2) enabling
//     the use of optional parameters to the key derivation function, which
//     strengthen the overall security and allow for binding the key material
//     to application-specific information (cf. RFC 5869,
//     https://tools.ietf.org/html/rfc5869)
//   - use of modern AEAD schemes rather than "manual composition" of symmetric
//     encryption with message authentication codes (as in DEM1, DEM2, and DEM3
//     schemes of ISO 18033-2)
package ecies

import (
	"fmt"

	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/internal/registryconfig"
)

func init() {
	if err := protoserialization.RegisterKeySerializer[*PublicKey](&publicKeySerializer{}); err != nil {
		panic(fmt.Sprintf("ecies.init() failed: %v", err))
	}
	if err := protoserialization.RegisterKeyParser(publicKeyTypeURL, &publicKeyParser{}); err != nil {
		panic(fmt.Sprintf("ecies.init() failed: %v", err))
	}
	if err := protoserialization.RegisterKeySerializer[*PrivateKey](&privateKeySerializer{}); err != nil {
		panic(fmt.Sprintf("ecies.init() failed: %v", err))
	}
	if err := protoserialization.RegisterKeyParser(privateKeyTypeURL, &privateKeyParser{}); err != nil {
		panic(fmt.Sprintf("ecies.init() failed: %v", err))
	}
	if err := protoserialization.RegisterParametersSerializer[*Parameters](&parametersSerializer{}); err != nil {
		panic(fmt.Sprintf("ecies.init() failed: %v", err))
	}
	if err := protoserialization.RegisterParametersParser(privateKeyTypeURL, &parametersParser{}); err != nil {
		panic(fmt.Sprintf("ecies.init() failed: %v", err))
	}
	if err := registry.RegisterKeyManager(new(privateKeyKeyManager)); err != nil {
		panic(fmt.Sprintf("ecies.init() failed: %v", err))
	}
	if err := registry.RegisterKeyManager(new(publicKeyKeyManager)); err != nil {
		panic(fmt.Sprintf("ecies.init() failed: %v", err))
	}
	if err := registryconfig.RegisterPrimitiveConstructor[*PublicKey](hybridEncryptConstructor); err != nil {
		panic(fmt.Sprintf("ecies.init() failed: %v", err))
	}
	if err := registryconfig.RegisterPrimitiveConstructor[*PrivateKey](hybridDecryptConstructor); err != nil {
		panic(fmt.Sprintf("ecies.init() failed: %v", err))
	}
}
