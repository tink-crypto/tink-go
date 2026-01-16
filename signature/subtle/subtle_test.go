// Copyright 2020 Google LLC
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

package subtle_test

import (
	"github.com/tink-crypto/tink-go/v2/internal/testing/wycheproof"
	"github.com/tink-crypto/tink-go/v2/testutil"
)

type ecdsaSuite struct {
	wycheproof.SuiteV1
	TestGroups []*ecdsaGroup `json:"testGroups"`
}

type ecdsaGroup struct {
	testutil.WycheproofGroup
	JWK          *ecdsaJWK     `json:"jwk,omitempty"`
	PublicKeyDER string        `json:"PublicKeyDer"`
	PublicKeyPEM string        `json:"PublicKeyPem"`
	SHA          string        `json:"sha"`
	PublicKey    *ecdsaTestKey `json:"PublicKey"`
	Tests        []*ecdsaCase  `json:"tests"`
}

type ecdsaCase struct {
	testutil.WycheproofCase
	Message   testutil.HexBytes `json:"msg"`
	Signature testutil.HexBytes `json:"sig"`
}

type ecdsaTestKey struct {
	Curve string `json:"curve"`
	Type  string `json:"type"`
	Wx    string `json:"wx"`
	Wy    string `json:"wy"`
}

type ecdsaJWK struct {
	JWK   string `json:"jwk"`
	Curve string `json:"crv"`
	Kid   string `json:"kid"`
	Kty   string `json:"kty"`
	X     string `json:"x"`
	Y     string `json:"y"`
}

type ed25519Suite struct {
	wycheproof.SuiteV1
	TestGroups []*ed25519Group `json:"testGroups"`
}

type ed25519Group struct {
	testutil.WycheproofGroup
	PublicKeyDER string          `json:"publicKeyDer"`
	PublicKeyPEM string          `json:"publicKeyPem"`
	SHA          string          `json:"sha"`
	PublicKey    *ed25519TestKey `json:"publicKey"`
	Tests        []*ed25519Case  `json:"tests"`
}

type ed25519Case struct {
	testutil.WycheproofCase
	Message   testutil.HexBytes `json:"msg"`
	Signature testutil.HexBytes `json:"sig"`
}

type ed25519TestKey struct {
	PK testutil.HexBytes `json:"pk"`
}
