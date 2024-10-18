// Copyright 2019 Google LLC
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

// Package signature provides implementations of the Signer and Verifier
// primitives.
//
// To sign data using Tink you can use ECDSA, ED25519 or RSA-SSA-PSS or
// RSA-SSA-PKCS1 key templates.
package signature

import (
	_ "github.com/tink-crypto/tink-go/v2/signature/ecdsa"             // register ecdsa key managers and keys
	_ "github.com/tink-crypto/tink-go/v2/signature/ed25519"         // register ed25519 key managers and keys
	_ "github.com/tink-crypto/tink-go/v2/signature/rsassapkcs1" // register rsassapkcs1 key managers
	_ "github.com/tink-crypto/tink-go/v2/signature/rsassapss"     // register rsassapss key managers
)
