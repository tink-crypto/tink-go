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
	"fmt"
	"math/big"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	_ "github.com/tink-crypto/tink-go/v2/signature/ecdsa" // register ECDSA key managers
	"github.com/tink-crypto/tink-go/v2/signature/subtle"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/testutil"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	ecdsapb "github.com/tink-crypto/tink-go/v2/proto/ecdsa_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

type ecdsaParams struct {
	hashType commonpb.HashType
	curve    commonpb.EllipticCurveType
}

func TestSignerKeyManagerGetPrimitiveBasic(t *testing.T) {
	testParams := genValidECDSAParams()
	keyManager, err := registry.GetKeyManager(testutil.ECDSASignerTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.ECDSASignerTypeURL, err)
	}
	for i := 0; i < len(testParams); i++ {
		serializedKey, err := proto.Marshal(testutil.NewRandomECDSAPrivateKey(testParams[i].hashType, testParams[i].curve))
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		_, err = keyManager.Primitive(serializedKey)
		if err != nil {
			t.Errorf("unexpect error in test case %d: %s ", i, err)
		}
	}
}

func TestSignerKeyManagerGetPrimitiveWithInvalidInput_InvalidParams(t *testing.T) {
	testParams := genInvalidECDSAParams()
	keyManager, err := registry.GetKeyManager(testutil.ECDSASignerTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.ECDSASignerTypeURL, err)
	}
	for i := 0; i < len(testParams); i++ {
		serializedKey, err := proto.Marshal(testutil.NewRandomECDSAPrivateKey(testParams[i].hashType, testParams[i].curve))
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		if _, err := keyManager.Primitive(serializedKey); err == nil {
			t.Errorf("expect an error in test case %d", i)
		}
	}
	for _, tc := range genUnkownECDSAParams() {
		k := testutil.NewRandomECDSAPrivateKey(commonpb.HashType_SHA256, commonpb.EllipticCurveType_NIST_P256)
		k.GetPublicKey().GetParams().Curve = tc.curve
		k.GetPublicKey().GetParams().HashType = tc.hashType
		serializedKey, err := proto.Marshal(k)
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		if _, err := keyManager.Primitive(serializedKey); err == nil {
			t.Errorf("expect an error in test case with params: (curve = %q, hash = %q)", tc.curve, tc.hashType)
		}
	}
}

func TestSignerKeyManagerGetPrimitiveWithInvalidInput_InvalidVersion(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.ECDSASignerTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.ECDSASignerTypeURL, err)
	}
	key := testutil.NewRandomECDSAPrivateKey(commonpb.HashType_SHA256,
		commonpb.EllipticCurveType_NIST_P256)
	key.Version = testutil.ECDSASignerKeyVersion + 1
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %q, want nil", err)
	}
	if _, err := keyManager.Primitive(serializedKey); err == nil {
		t.Errorf("expect an error when version is invalid")
	}
}

func TestSignerKeyManagerGetPrimitiveWithInvalidInput_NilInputAndParams(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.ECDSASignerTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.ECDSASignerTypeURL, err)
	}
	// Nil or empty input.
	if _, err := keyManager.Primitive(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	if _, err := keyManager.Primitive([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty slice")
	}
	// Nil params field.
	keyNilParams := testutil.NewRandomECDSAPrivateKey(commonpb.HashType_SHA256,
		commonpb.EllipticCurveType_NIST_P256)
	keyNilParams.GetPublicKey().Params = nil
	serializedKeyNilParams, err := proto.Marshal(keyNilParams)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %q, want nil", err)
	}
	if _, err := keyManager.Primitive(serializedKeyNilParams); err == nil {
		t.Errorf("keyManager.Primitive(serializedKeyNilParams) err = nil, want not nil")
	}
}

func TestSignerKeyManagerNewKeyBasic(t *testing.T) {
	testParams := genValidECDSAParams()
	keyManager, err := registry.GetKeyManager(testutil.ECDSASignerTypeURL)
	if err != nil {
		t.Fatalf("cannot obtain ECDSA signer key manager: %s", err)
	}
	for i := 0; i < len(testParams); i++ {
		params := testutil.NewECDSAParams(testParams[i].hashType, testParams[i].curve,
			ecdsapb.EcdsaSignatureEncoding_DER)
		serializedFormat, err := proto.Marshal(testutil.NewECDSAKeyFormat(params))
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		tmp, err := keyManager.NewKey(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		key := tmp.(*ecdsapb.EcdsaPrivateKey)
		validateECDSAPrivateKey(t, key, params)
	}
}

func TestSignerKeyManagerNewKeyWithInvalidInput_HashAndCurveType(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.ECDSASignerTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.ECDSASignerTypeURL, err)
	}
	testParams := genInvalidECDSAParams()
	for i := 0; i < len(testParams); i++ {
		params := testutil.NewECDSAParams(testParams[i].hashType, testParams[i].curve,
			ecdsapb.EcdsaSignatureEncoding_DER)
		serializedFormat, err := proto.Marshal(testutil.NewECDSAKeyFormat(params))
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		if _, err := keyManager.NewKey(serializedFormat); err == nil {
			t.Errorf("expect an error in test case %d", i)
		}
	}
}
func TestSignerKeyManagerNewKeyWithInvalidInput_InvalidEncoding(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.ECDSASignerTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.ECDSASignerTypeURL, err)
	}
	// invalid encoding
	testParams := genValidECDSAParams()
	for i := 0; i < len(testParams); i++ {
		params := testutil.NewECDSAParams(testParams[i].hashType, testParams[i].curve,
			ecdsapb.EcdsaSignatureEncoding_UNKNOWN_ENCODING)
		serializedFormat, err := proto.Marshal(testutil.NewECDSAKeyFormat(params))
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		if _, err := keyManager.NewKey(serializedFormat); err == nil {
			t.Errorf("expect an error in test case %d", i)
		}
	}
}

func TestSignerKeyManagerNewKeyWithInvalidInput_NilInputOrParameters(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.ECDSASignerTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.ECDSASignerTypeURL, err)
	}
	// Nil or empty input.
	if _, err := keyManager.NewKey(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	if _, err := keyManager.NewKey([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty slice")
	}
	// Nil params field.
	keyFormatNilParams := testutil.NewECDSAKeyFormat(nil)
	serializedKeyFormatNilParams, err := proto.Marshal(keyFormatNilParams)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %q, want nil", err)
	}
	if _, err := keyManager.NewKey(serializedKeyFormatNilParams); err == nil {
		t.Errorf("keyManager.newKey(serializedKeyFormatNilParams) err = nil, want not nil")
	}
}

func TestSignerKeyManagerPrivateKeyManagerGetPublicKeyErrors(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.ECDSASignerTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.ECDSASignerTypeURL, err)
	}
	testCases := []struct {
		name string
		key  []byte
	}{
		{
			name: "nil_key",
			key:  nil,
		},
		{
			name: "invalid_version",
			key: func() []byte {
				k := testutil.NewRandomECDSAPrivateKey(commonpb.HashType_SHA256, commonpb.EllipticCurveType_NIST_P256)
				k.Version = 1
				return mustMarshal(t, k)
			}(),
		},
		{
			name: "invalid_public_key_version",
			key: func() []byte {
				k := testutil.NewRandomECDSAPrivateKey(commonpb.HashType_SHA256, commonpb.EllipticCurveType_NIST_P256)
				k.GetPublicKey().Version = 1
				return mustMarshal(t, k)
			}(),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := keyManager.(registry.PrivateKeyManager).PublicKeyData(tc.key); err == nil {
				t.Fatalf("keyManager.PublicKeyData(serilizedPrivateKey) err = nil, want non-nil")
			}
		})
	}
}

func TestSignerKeyManagerNewKeyMultipleTimes(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.ECDSASignerTypeURL)
	if err != nil {
		t.Fatalf("cannot obtain ECDSA signer key manager: %s", err)
	}
	testParams := genValidECDSAParams()
	nTest := 27
	for i := 0; i < len(testParams); i++ {
		keys := make(map[string]bool)
		params := testutil.NewECDSAParams(testParams[i].hashType, testParams[i].curve,
			ecdsapb.EcdsaSignatureEncoding_DER)
		format := testutil.NewECDSAKeyFormat(params)
		serializedFormat, err := proto.Marshal(format)
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		for j := 0; j < nTest; j++ {
			key, err := keyManager.NewKey(serializedFormat)
			if err != nil {
				t.Fatalf("proto.Marshal() err = %q, want nil", err)
			}
			serializedKey, err := proto.Marshal(key)
			if err != nil {
				t.Fatalf("proto.Marshal() err = %q, want nil", err)
			}
			keys[string(serializedKey)] = true

			keyData, err := keyManager.NewKeyData(serializedFormat)
			if err != nil {
				t.Fatalf("keyManager.NewKeyData() err = %q, want nil", err)
			}
			serializedKey = keyData.Value
			keys[string(serializedKey)] = true
		}
		if len(keys) != nTest*2 {
			t.Errorf("key is repeated with params: %s", params)
		}
	}
}

func TestSignerKeyManagerNewKeyDataBasic(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.ECDSASignerTypeURL)
	if err != nil {
		t.Fatalf("cannot obtain ECDSA signer key manager: %s", err)
	}
	testParams := genValidECDSAParams()
	for i := 0; i < len(testParams); i++ {
		params := testutil.NewECDSAParams(testParams[i].hashType, testParams[i].curve,
			ecdsapb.EcdsaSignatureEncoding_DER)
		serializedFormat, err := proto.Marshal(testutil.NewECDSAKeyFormat(params))
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}

		keyData, err := keyManager.NewKeyData(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error in test case  %d: %s", i, err)
		}
		if keyData.TypeUrl != testutil.ECDSASignerTypeURL {
			t.Errorf("incorrect type url in test case  %d: expect %s, got %s",
				i, testutil.ECDSASignerTypeURL, keyData.TypeUrl)
		}
		if keyData.KeyMaterialType != tinkpb.KeyData_ASYMMETRIC_PRIVATE {
			t.Errorf("incorrect key material type in test case  %d: expect %s, got %s",
				i, tinkpb.KeyData_ASYMMETRIC_PRIVATE, keyData.KeyMaterialType)
		}
		key := new(ecdsapb.EcdsaPrivateKey)
		if err := proto.Unmarshal(keyData.Value, key); err != nil {
			t.Errorf("unexpect error in test case %d: %s", i, err)
		}
		validateECDSAPrivateKey(t, key, params)
	}
}

func TestSignerKeyManagerNewKeyDataWithInvalidInput(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.ECDSASignerTypeURL)
	if err != nil {
		t.Fatalf("cannot obtain ECDSA signer key manager: %s", err)
	}
	testParams := genInvalidECDSAParams()
	for i := 0; i < len(testParams); i++ {
		params := testutil.NewECDSAParams(testParams[i].hashType, testParams[i].curve,
			ecdsapb.EcdsaSignatureEncoding_DER)
		format := testutil.NewECDSAKeyFormat(params)
		serializedFormat, err := proto.Marshal(format)
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		if _, err := keyManager.NewKeyData(serializedFormat); err == nil {
			t.Errorf("expect an error in test case  %d", i)
		}
	}
	// nil input
	if _, err := keyManager.NewKeyData(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
}

func TestPublicKeyDataBasic(t *testing.T) {
	testParams := genValidECDSAParams()
	keyManager, err := registry.GetKeyManager(testutil.ECDSASignerTypeURL)
	if err != nil {
		t.Fatalf("cannot obtain ECDSA signer key manager: %s", err)
	}
	privateKeyManager, ok := keyManager.(registry.PrivateKeyManager)
	if !ok {
		t.Errorf("cannot obtain private key manager")
	}
	for i := 0; i < len(testParams); i++ {
		key := testutil.NewRandomECDSAPrivateKey(testParams[i].hashType, testParams[i].curve)
		serializedKey, err := proto.Marshal(key)
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}

		pubKeyData, err := privateKeyManager.PublicKeyData(serializedKey)
		if err != nil {
			t.Errorf("unexpect error in test case %d: %s ", i, err)
		}
		if pubKeyData.TypeUrl != testutil.ECDSAVerifierTypeURL {
			t.Errorf("incorrect type url: %s", pubKeyData.TypeUrl)
		}
		if pubKeyData.KeyMaterialType != tinkpb.KeyData_ASYMMETRIC_PUBLIC {
			t.Errorf("incorrect key material type: %d", pubKeyData.KeyMaterialType)
		}
		pubKey := new(ecdsapb.EcdsaPublicKey)
		if err = proto.Unmarshal(pubKeyData.Value, pubKey); err != nil {
			t.Errorf("invalid public key: %s", err)
		}
	}
}

func TestPublicKeyDataWithInvalidInput(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.ECDSASignerTypeURL)
	if err != nil {
		t.Fatalf("cannot obtain ECDSA signer key manager: %s", err)
	}
	privateKeyManager, ok := keyManager.(registry.PrivateKeyManager)
	if !ok {
		t.Errorf("cannot obtain private key manager")
	}
	// modified key
	key := testutil.NewRandomECDSAPrivateKey(commonpb.HashType_SHA256,
		commonpb.EllipticCurveType_NIST_P256)
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %q, want nil", err)
	}
	serializedKey[0] = 0
	if _, err := privateKeyManager.PublicKeyData(serializedKey); err == nil {
		t.Errorf("expect an error when input is a modified serialized key")
	}
	// invalid with a single byte
	if _, err := privateKeyManager.PublicKeyData([]byte{42}); err == nil {
		t.Errorf("expect an error when input is an empty slice")
	}
}

var errSmallKey = fmt.Errorf("private key doesn't have adequate size")

func validateECDSAPrivateKey(t *testing.T, key *ecdsapb.EcdsaPrivateKey, params *ecdsapb.EcdsaParams) {
	t.Helper()
	if key.Version != testutil.ECDSASignerKeyVersion {
		t.Fatalf("incorrect private key's version: expect %d, got %d", testutil.ECDSASignerKeyVersion, key.Version)
	}
	publicKey := key.PublicKey
	if publicKey.Version != testutil.ECDSASignerKeyVersion {
		t.Fatalf("incorrect public key's version: expect %d, got %d", testutil.ECDSASignerKeyVersion, key.Version)
	}
	if params.HashType != publicKey.Params.HashType ||
		params.Curve != publicKey.Params.Curve ||
		params.Encoding != publicKey.Params.Encoding {
		t.Fatalf("incorrect params: expect %s, got %s", params, publicKey.Params)
	}
	if len(publicKey.X) == 0 || len(publicKey.Y) == 0 {
		t.Fatalf("public points are not initialized")
	}
	// check private key's size
	d := new(big.Int).SetBytes(key.KeyValue)
	keySize := len(d.Bytes())
	switch params.Curve {
	case commonpb.EllipticCurveType_NIST_P256:
		if keySize < 256/8-8 || keySize > 256/8+1 {
			t.Fatal(errSmallKey)
		}
	case commonpb.EllipticCurveType_NIST_P384:
		if keySize < 384/8-8 || keySize > 384/8+1 {
			t.Fatal(errSmallKey)
		}
	case commonpb.EllipticCurveType_NIST_P521:
		if keySize < 521/8-8 || keySize > 521/8+1 {
			t.Fatal(errSmallKey)
		}
	}
	// try to sign and verify with the key
	hash, curve, encoding := testutil.GetECDSAParamNames(publicKey.Params)
	signer, err := subtle.NewECDSASigner(hash, curve, encoding, key.KeyValue)
	if err != nil {
		t.Fatalf("unexpected error when creating ECDSASign: %s", err)
	}
	verifier, err := subtle.NewECDSAVerifier(hash, curve, encoding, publicKey.X, publicKey.Y)
	if err != nil {
		t.Fatalf("unexpected error when creating ECDSAVerify: %s", err)
	}
	data := random.GetRandomBytes(1281)
	signature, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("unexpected error when signing: %s", err)
	}
	if err := verifier.Verify(signature, data); err != nil {
		t.Fatalf("unexpected error when verifying signature: %s", err)
	}
}

func genValidECDSAParams() []ecdsaParams {
	return []ecdsaParams{
		ecdsaParams{
			hashType: commonpb.HashType_SHA256,
			curve:    commonpb.EllipticCurveType_NIST_P256,
		},
		ecdsaParams{
			hashType: commonpb.HashType_SHA384,
			curve:    commonpb.EllipticCurveType_NIST_P384,
		},
		ecdsaParams{
			hashType: commonpb.HashType_SHA512,
			curve:    commonpb.EllipticCurveType_NIST_P384,
		},
		ecdsaParams{
			hashType: commonpb.HashType_SHA512,
			curve:    commonpb.EllipticCurveType_NIST_P521,
		},
	}
}

func genUnkownECDSAParams() []ecdsaParams {
	return []ecdsaParams{
		ecdsaParams{
			hashType: commonpb.HashType_UNKNOWN_HASH,
			curve:    commonpb.EllipticCurveType_NIST_P256,
		},
		ecdsaParams{
			hashType: commonpb.HashType_SHA256,
			curve:    commonpb.EllipticCurveType_UNKNOWN_CURVE,
		},
	}
}

func genInvalidECDSAParams() []ecdsaParams {
	return []ecdsaParams{
		ecdsaParams{
			hashType: commonpb.HashType_SHA1,
			curve:    commonpb.EllipticCurveType_NIST_P256,
		},
		ecdsaParams{
			hashType: commonpb.HashType_SHA1,
			curve:    commonpb.EllipticCurveType_NIST_P384,
		},
		ecdsaParams{
			hashType: commonpb.HashType_SHA1,
			curve:    commonpb.EllipticCurveType_NIST_P521,
		},
		ecdsaParams{
			hashType: commonpb.HashType_SHA256,
			curve:    commonpb.EllipticCurveType_NIST_P384,
		},
		ecdsaParams{
			hashType: commonpb.HashType_SHA256,
			curve:    commonpb.EllipticCurveType_NIST_P521,
		},
		ecdsaParams{
			hashType: commonpb.HashType_SHA512,
			curve:    commonpb.EllipticCurveType_NIST_P256,
		},
	}
}

func mustMarshal(t *testing.T, msg proto.Message) []byte {
	t.Helper()
	serialized, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", msg, err)
	}
	return serialized
}
