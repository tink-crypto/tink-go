// Copyright 2022 Google LLC
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

package jwt

import (
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	jepb "github.com/tink-crypto/tink-go/v2/proto/jwt_ecdsa_go_proto"
)

const testECDSAVerifierKeyType = "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey"

func TestECDSAVerifierNotImplemented(t *testing.T) {
	km, err := registry.GetKeyManager(testECDSAVerifierKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testECDSAVerifierKeyType, err)
	}
	if _, err := km.NewKey(nil); err == nil {
		t.Errorf("km.NewKey() err = nil, want error")
	}
}

func TestECDSAVerifierDoesSupport(t *testing.T) {
	km, err := registry.GetKeyManager(testECDSAVerifierKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testECDSAVerifierKeyType, err)
	}
	if !km.DoesSupport(testECDSAVerifierKeyType) {
		t.Errorf("km.DoesSupport(%q) = false, want true", testECDSAVerifierKeyType)
	}
	if km.DoesSupport("not.the.actual.key.type") {
		t.Errorf("km.DoesSupport('not.the.actual.key.type') = true, want false")
	}
}

func TestECDSAVerifierTypeURL(t *testing.T) {
	km, err := registry.GetKeyManager(testECDSAVerifierKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testECDSAVerifierKeyType, err)
	}
	if km.TypeURL() != testECDSAVerifierKeyType {
		t.Errorf("km.TypeURL() = %q, want %q", km.TypeURL(), testECDSAVerifierKeyType)
	}
}

func createECDSAPublicKey(algorithm jepb.JwtEcdsaAlgorithm, kid *string, version uint32) (*jepb.JwtEcdsaPublicKey, error) {
	// Public key from: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.3
	x, err := base64Decode("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU")
	if err != nil {
		return nil, fmt.Errorf("base64 decoding x coordinate of public key: %v", err)
	}
	y, err := base64Decode("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")
	if err != nil {
		return nil, fmt.Errorf("base64 decoding y coordinate of public key: %v", err)
	}
	var customKID *jepb.JwtEcdsaPublicKey_CustomKid = nil
	if kid != nil {
		customKID = &jepb.JwtEcdsaPublicKey_CustomKid{Value: *kid}
	}
	return &jepb.JwtEcdsaPublicKey{
		Version:   version,
		Algorithm: algorithm,
		X:         x,
		Y:         y,
		CustomKid: customKID,
	}, nil
}

func createECDSASerializedPublicKey(algorithm jepb.JwtEcdsaAlgorithm, kid *string, version uint32) ([]byte, error) {
	pubKey, err := createECDSAPublicKey(algorithm, kid, version)
	if err != nil {
		return nil, err
	}
	return proto.Marshal(pubKey)
}

func TestECDSAVerifierPrimitiveAlwaysFails(t *testing.T) {
	km, err := registry.GetKeyManager(testECDSAVerifierKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testECDSAVerifierKeyType, err)
	}
	serializedPubKey, err := createECDSASerializedPublicKey(jepb.JwtEcdsaAlgorithm_ES256, refString("1234"), 0 /*=version*/)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.Primitive(serializedPubKey); err == nil {
		t.Errorf("km.Primitive() err = %v, want nil", err)
	}
}
