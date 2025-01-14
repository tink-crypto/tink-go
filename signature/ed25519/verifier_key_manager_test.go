// Copyright 2018 Google LLC
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

package ed25519_test

import (
	"encoding/hex"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	tinked25519 "github.com/tink-crypto/tink-go/v2/signature/ed25519"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func TestVerifierKeyManagerGetPrimitiveBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.ED25519VerifierTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.ED25519VerifierTypeURL, err)
	}
	// Taken from https://datatracker.ietf.org/doc/html/rfc8032#section-7.1 - TEST 3.
	message := []byte{0xaf, 0x82}
	signatureHex := "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
	wantSignature, err := hex.DecodeString(signatureHex)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) err = %v, want nil", signatureHex, err)
	}
	params, err := tinked25519.NewParameters(tinked25519.VariantNoPrefix)
	if err != nil {
		t.Fatalf("tinked25519.NewParameters(%v) err = %v, want nil", tinked25519.VariantNoPrefix, err)
	}
	publicKeyBytes, _ := getTestKeyPair(t)
	publicKey, err := tinked25519.NewPublicKey(publicKeyBytes, 0, params)
	if err != nil {
		t.Fatalf("tinked25519.NewPublicKey(%v, %v, %v) err = %v, want nil", publicKeyBytes, 0, params, err)
	}

	keySerialization, err := protoserialization.SerializeKey(publicKey)
	if err != nil {
		t.Fatalf("protoserialization.SerializeKey(%v) err = %v, want nil", publicKey, err)
	}
	p, err := km.Primitive(keySerialization.KeyData().GetValue())
	if err != nil {
		t.Fatalf("km.Primitive(keySerialization.KeyData().GetValue()) err = %v, want nil", err)
	}
	v, ok := p.(tink.Verifier)
	if !ok {
		t.Fatalf("km.Primitive(keySerialization.KeyData().GetValue()) = %T, want %T", p, (tink.Verifier)(nil))
	}
	if err := v.Verify(wantSignature, message); err != nil {
		t.Errorf("v.Verify(%x, %x) err = %v, want nil", wantSignature, message, err)
	}
}

func TestVerifierKeyManagerGetPrimitiveWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.ED25519VerifierTypeURL)
	if err != nil {
		t.Errorf("cannot obtain ED25519Verifier key manager: %s", err)
	}

	// invalid version
	key := testutil.NewED25519PublicKey()
	key.Version = testutil.ED25519VerifierKeyVersion + 1
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %q, want nil", err)
	}
	if _, err := km.Primitive(serializedKey); err == nil {
		t.Errorf("expect an error when version is invalid")
	}
	// nil input
	if _, err := km.Primitive(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	if _, err := km.Primitive([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty slice")
	}
}
