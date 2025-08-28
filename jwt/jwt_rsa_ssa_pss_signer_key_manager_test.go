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
	"math/big"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	jrsppb "github.com/tink-crypto/tink-go/v2/proto/jwt_rsa_ssa_pss_go_proto"
	tpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const testJWTPSSignerKeyType = "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPrivateKey"

func makeValidJWTPSPrivateKey() (*jrsppb.JwtRsaSsaPssPrivateKey, error) {
	// key taken from: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2
	pubKey, err := makeValidPSPublicKey()
	if err != nil {
		return nil, err
	}
	d, err := base64Decode(
		"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I" +
			"jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0" +
			"BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn" +
			"439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT" +
			"CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh" +
			"BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ")
	if err != nil {
		return nil, err
	}
	p, err := base64Decode(
		"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi" +
			"YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG" +
			"BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc")
	if err != nil {
		return nil, err
	}
	q, err := base64Decode(
		"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa" +
			"ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA" +
			"-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc")
	if err != nil {
		return nil, err
	}
	dp, err := base64Decode(
		"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q" +
			"CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb" +
			"34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0")
	if err != nil {
		return nil, err
	}
	dq, err := base64Decode(
		"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa" +
			"7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky" +
			"NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU")
	if err != nil {
		return nil, err
	}
	qi, err := base64Decode(
		"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o" +
			"y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU" +
			"W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U")
	if err != nil {
		return nil, err
	}
	return &jrsppb.JwtRsaSsaPssPrivateKey{
		PublicKey: pubKey,
		Version:   0,
		D:         d,
		P:         p,
		Q:         q,
		Dp:        dp,
		Dq:        dq,
		Crt:       qi,
	}, nil
}

func TestJWTPSSignerKeyManagerDoesSupport(t *testing.T) {
	km, err := registry.GetKeyManager(testJWTPSSignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTPSSignerKeyType, err)
	}
	if !km.DoesSupport(testJWTPSSignerKeyType) {
		t.Errorf("DoesSupport(%q) = false, want true", testJWTPSSignerKeyType)
	}
	if km.DoesSupport("invalid.key.type") {
		t.Errorf("DoesSupport(%q) = true, want false", "invalid.key.type")
	}
}

func TestJWTPSSignerKeyManagerTypeURL(t *testing.T) {
	km, err := registry.GetKeyManager(testJWTPSSignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTPSSignerKeyType, err)
	}
	if km.TypeURL() != testJWTPSSignerKeyType {
		t.Errorf("TypeURL() = %v, want = %v", km.TypeURL(), testJWTPSSignerKeyType)
	}
}

func TestJWTPSSignerPrimitiveAlwaysFails(t *testing.T) {
	km, err := registry.GetKeyManager(testJWTPSSignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTPSSignerKeyType, err)
	}
	privKey, err := makeValidJWTPSPrivateKey()
	if err != nil {
		t.Fatalf("makeValidJWTPSPrivateKey() err = %v, want nil", err)
	}
	serializedPrivKey, err := proto.Marshal(privKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	if _, err := km.Primitive(serializedPrivKey); err == nil {
		t.Errorf("Primitive() err = nil, want error")
	}
}

func TestJWTPSSignerKeyManagerPublicKeyData(t *testing.T) {
	km, err := registry.GetKeyManager(testJWTPSSignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTPSSignerKeyType, err)
	}
	privKey, err := makeValidJWTPSPrivateKey()
	if err != nil {
		t.Fatalf("makeValidJWTPSPrivateKey() err = %v, want nil", err)
	}
	serializedPrivKey, err := proto.Marshal(privKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	pubKeyData, err := km.(registry.PrivateKeyManager).PublicKeyData(serializedPrivKey)
	if err != nil {
		t.Fatalf("PublicKeyData() err = %v, want nil", err)
	}
	if pubKeyData.GetKeyMaterialType() != tpb.KeyData_ASYMMETRIC_PUBLIC {
		t.Errorf("GetKeyMaterialType() = %v, want %v", pubKeyData.GetKeyMaterialType(), tpb.KeyData_ASYMMETRIC_PUBLIC)
	}
	if pubKeyData.GetTypeUrl() != testJWTPSVerifierKeyType {
		t.Errorf("TypeURL() = %v, want %v", pubKeyData.GetTypeUrl(), testJWTPSVerifierKeyType)
	}
	gotPubKey := &jrsppb.JwtRsaSsaPssPublicKey{}
	if err := proto.Unmarshal(pubKeyData.GetValue(), gotPubKey); err != nil {
		t.Fatalf("proto.Unmarshal() err = %v, want nil", err)
	}
	if !cmp.Equal(gotPubKey, privKey.GetPublicKey(), protocmp.Transform()) {
		t.Errorf("got = %v, want = %v", gotPubKey, privKey.GetPublicKey())
	}
}

func TestJWTPSSignerKeyManagerNewKeyData(t *testing.T) {
	km, err := registry.GetKeyManager(testJWTPSSignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTPSSignerKeyType, err)
	}
	keyFormat := &jrsppb.JwtRsaSsaPssKeyFormat{
		Version:           0,
		Algorithm:         jrsppb.JwtRsaSsaPssAlgorithm_PS256,
		ModulusSizeInBits: 3072,
		PublicExponent:    []byte{0x01, 0x00, 0x01},
	}
	serializedKeyFormat, err := proto.Marshal(keyFormat)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	keyData, err := km.NewKeyData(serializedKeyFormat)
	if err != nil {
		t.Fatalf("NewKeyData() err = %v, want nil", err)
	}
	if keyData.GetTypeUrl() != testJWTPSSignerKeyType {
		t.Errorf("GetTypeURL() = %v, want %v", keyData.GetTypeUrl(), testJWTPSSignerKeyType)
	}
	if keyData.GetKeyMaterialType() != tpb.KeyData_ASYMMETRIC_PRIVATE {
		t.Errorf("GetKeyMaterialType() = %v, want %v", keyData.GetKeyMaterialType(), tpb.KeyData_ASYMMETRIC_PRIVATE)
	}
	key := &jrsppb.JwtRsaSsaPssPrivateKey{}
	if err := proto.Unmarshal(keyData.GetValue(), key); err != nil {
		t.Fatalf("proto.Unmarshal() err = %v, want nil", err)
	}
	pubKey := key.GetPublicKey()
	if pubKey.GetAlgorithm() != keyFormat.GetAlgorithm() {
		t.Errorf("GetAlgorithm() = %v, want %v", pubKey.GetAlgorithm(), keyFormat.GetAlgorithm())
	}
	if !cmp.Equal(pubKey.GetE(), keyFormat.GetPublicExponent()) {
		t.Errorf("Exponent = %v, want %v", pubKey.GetE(), keyFormat.GetPublicExponent())
	}
	modSize := new(big.Int).SetBytes(pubKey.GetN()).BitLen()
	if modSize != int(keyFormat.GetModulusSizeInBits()) {
		t.Errorf("Modulus Size in Bits = %d, want %d", modSize, keyFormat.GetModulusSizeInBits())
	}
}

func TestJWTPSSignerKeyManagerNewKeyDataFailsWithInvalidFormat(t *testing.T) {
	type testCase struct {
		name      string
		keyFormat *jrsppb.JwtRsaSsaPssKeyFormat
	}
	km, err := registry.GetKeyManager(testJWTPSSignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTPSSignerKeyType, err)
	}
	for _, tc := range []testCase{
		{
			name:      "nil key format",
			keyFormat: nil,
		},
		{
			name:      "empty key format",
			keyFormat: &jrsppb.JwtRsaSsaPssKeyFormat{},
		},
		{
			name: "invalid version",
			keyFormat: &jrsppb.JwtRsaSsaPssKeyFormat{
				Algorithm:         jrsppb.JwtRsaSsaPssAlgorithm_PS256,
				Version:           1,
				PublicExponent:    []byte{0x01, 0x00, 0x01},
				ModulusSizeInBits: 3072,
			},
		},
		{
			name: "invalid algorithm",
			keyFormat: &jrsppb.JwtRsaSsaPssKeyFormat{
				Algorithm:         jrsppb.JwtRsaSsaPssAlgorithm_PS_UNKNOWN,
				Version:           0,
				PublicExponent:    []byte{0x01, 0x00, 0x01},
				ModulusSizeInBits: 3072,
			},
		},
		{
			name: "invalid public exponent",
			keyFormat: &jrsppb.JwtRsaSsaPssKeyFormat{
				Algorithm:         jrsppb.JwtRsaSsaPssAlgorithm_PS256,
				Version:           0,
				PublicExponent:    []byte{0x01},
				ModulusSizeInBits: 3072,
			},
		},
		{
			name: "invalid modulus size",
			keyFormat: &jrsppb.JwtRsaSsaPssKeyFormat{
				Algorithm:         jrsppb.JwtRsaSsaPssAlgorithm_PS256,
				Version:           0,
				PublicExponent:    []byte{0x01, 0x00, 0x01},
				ModulusSizeInBits: 1024,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serializedKeyFormat, err := proto.Marshal(tc.keyFormat)
			if err != nil {
				t.Fatalf("proto.Marshal() err = %v, want nil", err)
			}
			if _, err := km.NewKeyData(serializedKeyFormat); err == nil {
				t.Fatalf("NewKeyData() err = nil, want error")
			}
			if _, err := km.NewKey(serializedKeyFormat); err == nil {
				t.Fatalf("NewKey() err = nil, want error")
			}
		})
	}
}

func TestJWTPSSignerKeyManagerNewKeyDataFailsWithNilKeyFormat(t *testing.T) {
	km, err := registry.GetKeyManager(testJWTPSSignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTPSSignerKeyType, err)
	}
	if _, err := km.NewKeyData(nil); err == nil {
		t.Fatalf("NewKeyData() err = nil, want error")
	}
	if _, err := km.NewKey(nil); err == nil {
		t.Fatalf("NewKey() err = nil, want error")
	}
}

func TestJWTPSSignerKeyManagerNewKeyDataFailsWithInvalidSerializedKeyFormat(t *testing.T) {
	km, err := registry.GetKeyManager(testJWTPSSignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTPSSignerKeyType, err)
	}
	if _, err := km.NewKeyData([]byte("invalid_serialization")); err == nil {
		t.Fatalf("NewKeyData() err = nil, want error")
	}
	if _, err := km.NewKey([]byte("invalid_serialization")); err == nil {
		t.Fatalf("NewKey() err = nil, want error")
	}
}
