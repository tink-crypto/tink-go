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
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	jepb "github.com/tink-crypto/tink-go/v2/proto/jwt_ecdsa_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	testECDSASignerKeyType = "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey"
	testECDSASignerVersion = 0
)

func TestECDSASignerDoesSupport(t *testing.T) {
	km, err := registry.GetKeyManager(testECDSASignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testECDSASignerKeyType, err)
	}
	if !km.DoesSupport(testECDSASignerKeyType) {
		t.Errorf("km.DoesSupport(%q) = false, want true", testECDSASignerKeyType)
	}
	if km.DoesSupport("not.the.actual.key.type") {
		t.Errorf("km.DoesSupport('not.the.actual.key.type') = true, want false")
	}
}

func TestECDSASignerTypeURL(t *testing.T) {
	km, err := registry.GetKeyManager(testECDSASignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testECDSASignerKeyType, err)
	}
	if km.TypeURL() != testECDSASignerKeyType {
		t.Errorf("km.TypeURL() = %q, want %q", km.TypeURL(), testECDSASignerKeyType)
	}
}

func TestECDSASignerNewKeyWithEmptyKeyFormatFails(t *testing.T) {
	km, err := registry.GetKeyManager(testECDSASignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testECDSASignerKeyType, err)
	}
	if _, err := km.NewKey(nil); err == nil {
		t.Errorf("km.NewKey(nil) err = nil, want error")
	}
}

func createECDSASerializedKeyFormat(algorithm jepb.JwtEcdsaAlgorithm, version uint32) ([]byte, error) {
	kf := &jepb.JwtEcdsaKeyFormat{
		Version:   version,
		Algorithm: algorithm,
	}
	return proto.Marshal(kf)
}

func TestECDSASignerNewKeyWithInvalidAlgorithmFails(t *testing.T) {
	km, err := registry.GetKeyManager(testECDSASignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testECDSASignerKeyType, err)
	}
	keyFormat, err := createECDSASerializedKeyFormat(jepb.JwtEcdsaAlgorithm_ES_UNKNOWN, testECDSASignerVersion)
	if err != nil {
		t.Fatalf("createECDSASerializedKeyFormat() err = %v, want nil", err)
	}
	if _, err := km.NewKey(keyFormat); err == nil {
		t.Errorf("km.NewKey(keyFormat) err = nil, want error")
	}
}

func TestECDSASignerNewKeyGeneratesValidKey(t *testing.T) {
	type testCase struct {
		tag       string
		algorithm jepb.JwtEcdsaAlgorithm
	}
	for _, tc := range []testCase{
		{
			tag:       "ES256",
			algorithm: jepb.JwtEcdsaAlgorithm_ES256,
		},
		{
			tag:       "ES384",
			algorithm: jepb.JwtEcdsaAlgorithm_ES384,
		},
		{
			tag:       "ES521",
			algorithm: jepb.JwtEcdsaAlgorithm_ES512,
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			km, err := registry.GetKeyManager(testECDSASignerKeyType)
			if err != nil {
				t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testECDSASignerKeyType, err)
			}
			keyFormat, err := createECDSASerializedKeyFormat(tc.algorithm, testECDSASignerVersion)
			if err != nil {
				t.Fatalf("createECDSASerializedKeyFormat() err = %v, want nil", err)
			}
			k, err := km.NewKey(keyFormat)
			if err != nil {
				t.Errorf("km.NewKey(keyFormat) err = %v, want nil", err)
			}
			key, ok := k.(*jepb.JwtEcdsaPrivateKey)
			if !ok {
				t.Errorf("key is not of type: *jepb.JwtEcdsaPrivateKey")
			}
			pubKey := key.GetPublicKey()
			if pubKey == nil {
				t.Errorf("pubKey = nil, want *jebp.JwtEcdsaPublicKey{}")
			}
			if pubKey.GetAlgorithm() != tc.algorithm {
				t.Errorf("pubKey.GetAlgorithm() = %q, want %q", pubKey.GetAlgorithm(), tc.algorithm)
			}
			if pubKey.GetVersion() != testECDSASignerVersion {
				t.Errorf("pubKey.GetVersion() = %d, want %d", pubKey.GetVersion(), testECDSASignerVersion)
			}
		})
	}
}

func TestECDSASignerNewKeyGeneratesDifferentKeys(t *testing.T) {
	km, err := registry.GetKeyManager(testECDSASignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testECDSASignerKeyType, err)
	}
	keyFormat, err := createECDSASerializedKeyFormat(jepb.JwtEcdsaAlgorithm_ES256, testECDSASignerVersion)
	if err != nil {
		t.Fatalf("createECDSASerializedKeyFormat() err = %v, want nil", err)
	}
	k1, err := km.NewKey(keyFormat)
	if err != nil {
		t.Errorf("km.NewKey(keyFormat) err = %v, want nil", err)
	}
	key1, ok := k1.(*jepb.JwtEcdsaPrivateKey)
	if !ok {
		t.Errorf("key1 is not of type: *jepb.JwtEcdsaPrivateKey")
	}
	k2, err := km.NewKey(keyFormat)
	if err != nil {
		t.Errorf("km.NewKey(keyFormat) err = %v, want nil", err)
	}
	key2, ok := k2.(*jepb.JwtEcdsaPrivateKey)
	if !ok {
		t.Errorf("key2 is not of type: *jepb.JwtEcdsaPrivateKey")
	}
	if cmp.Equal(key1.GetKeyValue(), key2.GetKeyValue()) {
		t.Errorf("keys should have different values")
	}
}

func TestECDSASignerNewKeyDataWithEmptyKeyFormatFails(t *testing.T) {
	km, err := registry.GetKeyManager(testECDSASignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testECDSASignerKeyType, err)
	}
	if _, err := km.NewKeyData(nil); err == nil {
		t.Errorf("km.NewKeyData(nil) err = nil, want error")
	}
}

func TestECDSASignerNewKeyDataWithInvalidAlgorithmFails(t *testing.T) {
	km, err := registry.GetKeyManager(testECDSASignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testECDSASignerKeyType, err)
	}
	keyFormat, err := createECDSASerializedKeyFormat(jepb.JwtEcdsaAlgorithm_ES_UNKNOWN, testECDSASignerVersion)
	if err != nil {
		t.Fatalf("createECDSASerializedKeyFormat() err = %v, want nil", err)
	}
	if _, err := km.NewKeyData(keyFormat); err == nil {
		t.Errorf("km.NewKeyData(keyFormat) err = %v, want %v", err, errECDSAInvalidAlgorithm)
	}
}

func TestECDSASignerNewKeyDataGeneratesValidKeyData(t *testing.T) {
	km, err := registry.GetKeyManager(testECDSASignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testECDSASignerKeyType, err)
	}
	keyFormat, err := createECDSASerializedKeyFormat(jepb.JwtEcdsaAlgorithm_ES256, testECDSASignerVersion)
	if err != nil {
		t.Fatalf("createECDSASerializedKeyFormat() err = %v, want nil", err)
	}
	keyData, err := km.NewKeyData(keyFormat)
	if err != nil {
		t.Errorf("km.NewKeyData(keyFormat) err = %v, want nil", err)
	}
	if keyData.GetTypeUrl() != testECDSASignerKeyType {
		t.Errorf("keyData.GetTypeUrl() = %q, want %q", keyData.GetTypeUrl(), testECDSASignerKeyType)
	}
	if keyData.GetKeyMaterialType() != tinkpb.KeyData_ASYMMETRIC_PRIVATE {
		t.Errorf("keyData.GetKeyMaterialType() = %q, want %q", keyData.GetKeyMaterialType(), tinkpb.KeyData_ASYMMETRIC_PRIVATE)
	}
}

func TestECDSASignerPublicKeyDataWithEmptyKeyFormatFails(t *testing.T) {
	km, err := registry.GetKeyManager(testECDSASignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testECDSASignerKeyType, err)
	}
	pkm, ok := km.(registry.PrivateKeyManager)
	if !ok {
		t.Fatalf("key manager is not of type registry.PrivateKeyManager")
	}
	if _, err := pkm.PublicKeyData(nil); err == nil {
		t.Errorf("km.PublicKeyData(nil) err = nil, want error")
	}
}

func createECDSAKey() (*jepb.JwtEcdsaPrivateKey, error) {
	// Private key from: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.3
	k, err := base64Decode("jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI")
	if err != nil {
		return nil, err
	}
	pubKey, err := createECDSAPublicKey(jepb.JwtEcdsaAlgorithm_ES256, nil /*=kid*/, testECDSASignerVersion)
	if err != nil {
		return nil, err
	}
	return &jepb.JwtEcdsaPrivateKey{
		Version:   testECDSASignerVersion,
		PublicKey: pubKey,
		KeyValue:  k,
	}, nil
}

func createSerializedECDSAKey() ([]byte, error) {
	key, err := createECDSAKey()
	if err != nil {
		return nil, err
	}
	return proto.Marshal(key)
}

func TestECDSASignerPublicKeyDataGeneratesValidKeyData(t *testing.T) {
	km, err := registry.GetKeyManager(testECDSASignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testECDSASignerKeyType, err)
	}
	pkm, ok := km.(registry.PrivateKeyManager)
	if !ok {
		t.Fatalf("key manager is not of type registry.PrivateKeyManager")
	}
	key, err := createSerializedECDSAKey()
	if err != nil {
		t.Fatalf("createECDSASerializedKeyFormat() err = %v, want nil", err)
	}
	pubKeyData, err := pkm.PublicKeyData(key)
	if err != nil {
		t.Fatalf("km.PublicKeyData() err = %v, want nil", err)
	}
	if pubKeyData.GetKeyMaterialType() != tinkpb.KeyData_ASYMMETRIC_PUBLIC {
		t.Fatalf("km.PublicKeyData() = %q, want %q", pubKeyData.GetKeyMaterialType(), tinkpb.KeyData_ASYMMETRIC_PUBLIC)
	}
	if pubKeyData.GetTypeUrl() != testECDSAVerifierKeyType {
		t.Errorf("keyData.GetTypeUrl() = %q, want %q", pubKeyData.GetTypeUrl(), testECDSAVerifierKeyType)
	}
}

func TestECDSASignerPrimitiveAlwaysFails(t *testing.T) {
	km, err := registry.GetKeyManager(testECDSASignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q): %v", testECDSASignerKeyType, err)
	}
	k, err := createECDSAKey()
	if err != nil {
		t.Fatal(err)
	}
	serializedKey, err := proto.Marshal(k)
	if err != nil {
		t.Fatalf("proto.Marshal(k) err = %v, want nil", err)
	}
	if _, err := km.Primitive(serializedKey); err == nil {
		t.Errorf("km.Primitive() err = nil, want error")
	}
}
