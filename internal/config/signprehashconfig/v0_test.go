// Copyright 2026 Google LLC
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

package signprehashconfig_test

import (
	"encoding/hex"
	"testing"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/config/signprehashconfig"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	tinkmldsa "github.com/tink-crypto/tink-go/v2/signature/mldsa"
	"github.com/tink-crypto/tink-go/v2/tink"
)

const (
	privKey65SeedHex = "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D"
)

func TestV0ConfigPrimitiveFromKey(t *testing.T) {
	c := signprehashconfig.V0()

	params, err := tinkmldsa.NewParameters(tinkmldsa.MLDSA65, tinkmldsa.VariantNoPrefixWithPrehashID)
	if err != nil {
		t.Fatalf("tinkmldsa.NewParameters() err = %v, want nil", err)
	}

	seedBytes, _ := hex.DecodeString(privKey65SeedHex)
	privKey, err := tinkmldsa.NewPrivateKey(
		secretdata.NewBytesFromData(seedBytes, insecuresecretdataaccess.Token{}),
		12345,
		params,
	)
	if err != nil {
		t.Fatalf("tinkmldsa.NewPrivateKey() err = %v, want nil", err)
	}

	pubKey, err := privKey.PublicKey()
	if err != nil {
		t.Fatalf("privKey.PublicKey() err = %v, want nil", err)
	}

	// 1. PrimitiveFromKey for PrehashSigner
	signerPrimitive, err := c.PrimitiveFromKey(privKey, internalapi.Token{})
	if err != nil {
		t.Fatalf("c.PrimitiveFromKey(privKey) err = %v, want nil", err)
	}
	if _, ok := signerPrimitive.(tink.PrehashSigner); !ok {
		t.Errorf("signerPrimitive is %T, want tink.PrehashSigner", signerPrimitive)
	}

	// 2. PrimitiveFromKey for Prehash
	prehashPrimitive, err := c.PrimitiveFromKey(pubKey, internalapi.Token{})
	if err != nil {
		t.Fatalf("c.PrimitiveFromKey(pubKey) err = %v, want nil", err)
	}
	if _, ok := prehashPrimitive.(tink.Prehash); !ok {
		t.Errorf("prehashPrimitive is %T, want tink.Prehash", prehashPrimitive)
	}
}
