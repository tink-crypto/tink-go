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

package ecdsa_test

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/testutil"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
)

func TestVerifierKeyManagerGetPrimitiveBasic(t *testing.T) {
	testParams := genValidECDSAParams()
	keyManager, err := registry.GetKeyManager(testutil.ECDSAVerifierTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.ECDSAVerifierTypeURL, err)
	}
	for i := 0; i < len(testParams); i++ {
		serializedKey, err := proto.Marshal(testutil.NewRandomECDSAPublicKey(testParams[i].hashType, testParams[i].curve))
		if err != nil {
			t.Errorf("proto.Marshal() err = %v, want nil", err)
		}
		_, err = keyManager.Primitive(serializedKey)
		if err != nil {
			t.Errorf("unexpect error in test case %d: %s ", i, err)
		}
	}
}

func TestVerifierKeyManagerWithInvalidPublicKeyFailsCreatingPrimitive(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.ECDSAVerifierTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.ECDSAVerifierTypeURL, err)
	}
	pubKey := testutil.NewRandomECDSAPublicKey(commonpb.HashType_SHA256, commonpb.EllipticCurveType_NIST_P256)
	pubKey.X = []byte{0, 32, 0}
	pubKey.Y = []byte{0, 32, 0}
	serializedPubKey, err := proto.Marshal(pubKey)
	if err != nil {
		t.Fatalf("proto.Marhsal() err = %v, want nil", err)
	}
	if _, err := keyManager.Primitive(serializedPubKey); err == nil {
		t.Errorf("keyManager.Primitive() err = nil, want error")
	}
}

func TestVerifierKeyManagerGetPrimitiveWithInvalidInput_InvalidParams(t *testing.T) {
	testParams := genInvalidECDSAParams()
	keyManager, err := registry.GetKeyManager(testutil.ECDSAVerifierTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.ECDSAVerifierTypeURL, err)
	}
	for i := 0; i < len(testParams); i++ {
		serializedKey, err := proto.Marshal(testutil.NewRandomECDSAPublicKey(testParams[i].hashType, testParams[i].curve))
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		if _, err := keyManager.Primitive(serializedKey); err == nil {
			t.Errorf("expect an error in test case %d", i)
		}
	}
	for _, tc := range genUnkownECDSAParams() {
		k := testutil.NewRandomECDSAPublicKey(commonpb.HashType_SHA256, commonpb.EllipticCurveType_NIST_P256)
		k.GetParams().Curve = tc.curve
		k.GetParams().HashType = tc.hashType
		serializedKey, err := proto.Marshal(k)
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		if _, err := keyManager.Primitive(serializedKey); err == nil {
			t.Errorf("expect an error in test case with params: (curve = %q, hash = %q)", tc.curve, tc.hashType)
		}
	}
}

func TestVerifierKeyManagerGetPrimitiveWithInvalidInput_InvalidVersion(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.ECDSAVerifierTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.ECDSAVerifierTypeURL, err)
	}
	key := testutil.NewRandomECDSAPublicKey(commonpb.HashType_SHA256, commonpb.EllipticCurveType_NIST_P256)
	key.Version = testutil.ECDSAVerifierKeyVersion + 1
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %q, want nil", err)
	}
	if _, err = keyManager.Primitive(serializedKey); err == nil {
		t.Errorf("expect an error when version is invalid")
	}
}

func TestVerifierKeyManagerGetPrimitiveWithInvalidInput_NilInputAndParams(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.ECDSAVerifierTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.ECDSAVerifierTypeURL, err)
	}
	// Nil or empty input.
	if _, err := keyManager.Primitive(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	if _, err := keyManager.Primitive([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty slice")
	}
	// Nil params.
	keyNilParams := testutil.NewRandomECDSAPublicKey(commonpb.HashType_SHA256, commonpb.EllipticCurveType_NIST_P256)
	keyNilParams.Params = nil
	serializedKeyNilParams, err := proto.Marshal(keyNilParams)
	if err != nil {
		t.Errorf("proto.Marshal() err = %q, want nil", err)
	}
	if _, err := keyManager.Primitive(serializedKeyNilParams); err == nil {
		t.Errorf("keyManager.Primitive(serializedKeyNilParams); err = nil, want non-nil")
	}
}
