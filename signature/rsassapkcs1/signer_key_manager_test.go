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

package rsassapkcs1_test

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapkcs1"
	_ "github.com/tink-crypto/tink-go/v2/signature/rsassapkcs1" // Register the key managers.
	"github.com/tink-crypto/tink-go/v2/tink"
	cpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	rsassapkcs1pb "github.com/tink-crypto/tink-go/v2/proto/rsa_ssa_pkcs1_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const privateKeyTypeURL = "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey"

func TestSignerKeyManagerDoesSupport(t *testing.T) {
	skm, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}
	if !skm.DoesSupport(privateKeyTypeURL) {
		t.Errorf("DoesSupport(%q) = false, want true", privateKeyTypeURL)
	}
	if skm.DoesSupport("not.valid.type") {
		t.Errorf("DoesSupport(%q) = true, want false", "not.valid.type")
	}
}

func TestTypeURL(t *testing.T) {
	skm, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}
	if skm.TypeURL() != privateKeyTypeURL {
		t.Errorf("TypeURL() = %q, want %q", skm.TypeURL(), privateKeyTypeURL)
	}
}

func TestSignerKeyManagerPublicKeyData(t *testing.T) {
	skm, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}
	vkm, err := registry.GetKeyManager(publicKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", publicKeyTypeURL, err)
	}
	privKey, err := makeValidRSAPKCS1Key()
	if err != nil {
		t.Fatalf("makeValidRSAPKCS1Key() err = %v, want nil", err)
	}
	serializedPrivate, err := proto.Marshal(privKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	got, err := skm.(registry.PrivateKeyManager).PublicKeyData(serializedPrivate)
	if err != nil {
		t.Fatalf("PublicKeyData() err = %v, want nil", err)
	}
	if got.GetKeyMaterialType() != tinkpb.KeyData_ASYMMETRIC_PUBLIC {
		t.Errorf("GetKeyMaterialType() = %q, want %q", got.GetKeyMaterialType(), tinkpb.KeyData_ASYMMETRIC_PUBLIC)
	}
	if got.GetTypeUrl() != publicKeyTypeURL {
		t.Errorf("GetTypeUrl() = %q, want %q", got.GetTypeUrl(), publicKeyTypeURL)
	}
	if _, err := vkm.Primitive(got.GetValue()); err != nil {
		t.Errorf("Primitive() err = %v, want nil", err)
	}
}

func TestSignerKeyManagerPrimitiveSignVerify(t *testing.T) {
	skm, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}
	// Test vector from https://github.com/tink-crypto/tink-java/tree/v1.15.0/src/main/java/com/google/crypto/tink/signature/internal/testing/RsaSsaPkcs1TestUtil.java#L35
	modulus2048Base64 := "t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRy" +
		"O125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP" +
		"8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0" +
		"Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0X" +
		"OC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1" +
		"_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q"
	publicKey := mustCreatePublicKey(t, mustDecodeBase64(t, modulus2048Base64), 0, mustCreateParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantNoPrefix))
	privateKey, err := rsassapkcs1.NewPrivateKey(publicKey, rsassapkcs1.PrivateKeyValues{
		P: secretdata.NewBytesFromData(mustDecodeBase64(t, "2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-PIHf"+
			"QP0FkxXVrx-WE-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk31s0Q8"+
			"UK96E3_OrADAYtAJs-M3JxCLfNgqh56HDnETTQhH3rCT5T3yJws"), insecuresecretdataaccess.Token{}),
		Q: secretdata.NewBytesFromData(mustDecodeBase64(t, "1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0c6I"+
			"edis4S7B_coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV8CLCYK"+
			"rYl52ziqK0E_ym2QnkwsUX7eYTB7LbAHRK9GqocDE5B0f808I4s"), insecuresecretdataaccess.Token{}),
		D: secretdata.NewBytesFromData(mustDecodeBase64(t, "GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTeaSTyWfS"+
			"NkuaAwnOEbIQVy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWaCl3hdlPKXy9U"+
			"vqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8dWBo4_PMaenNnPiQgO0xnu"+
			"ToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDmsXOfUENOyMqADC6p1M3h33tsu"+
			"rY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1yX8C1EWmeRDkK2a"+
			"hecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ"), insecuresecretdataaccess.Token{}),
	})
	if err != nil {
		t.Fatalf("rsassapkcs1.NewPrivateKey() err = %v, want nil", err)
	}
	message, err := hex.DecodeString("aa")
	if err != nil {
		t.Fatalf("hex.DecodeString(%v) = %v, want nil", "aa", err)
	}
	wantSig, err := hex.DecodeString("3d10ce911833c1fe3f3356580017d159e1557e019096499950f62c3768c716bca418828dc140e930ecceff" +
		"ebc532db66c77b433e51cef6dfbac86cb3aff6f5fc2a488faf35199b2e12c9fe2de7be3eea63bdc9" +
		"60e6694e4474c29e5610f5f7fa30ac23b015041353658c74998c3f620728b5859bad9c63d07be0b2" +
		"d3bbbea8b9121f47385e4cad92b31c0ef656eee782339d14fd6350bb3756663c03cb261f7ece6e03" +
		"355c7a4ecfe812c965f68890b2571916de0e2cd40814f9db9571065b5340ef7aa66d55a78cd62f4a" +
		"1bd496623184a3d29dd886c1d1331754915bcbb243e5677ea7bb21a18d1ee22b6ba92c15a23ed6ae" +
		"de20abc29b290cc04fa0846027")
	if err != nil {
		t.Fatalf("hex.DecodeString() = %v, want nil", err)
	}
	keySerialization, err := protoserialization.SerializeKey(privateKey)
	if err != nil {
		t.Fatalf("protoserialization.SerializeKey(privateKey) err = %v, want nil", err)
	}
	p, err := skm.Primitive(keySerialization.KeyData().GetValue())
	if err != nil {
		t.Fatalf("skm.Primitive(keySerialization.KeyData().GetValue())) err = %v, want nil", err)
	}
	s, ok := p.(tink.Signer)
	if !ok {
		t.Fatalf("vkm.Primitive(keySerialization.KeyData().GetValue()) = %T, want %T", p, (tink.Signer)(nil))
	}
	got, err := s.Sign(message)
	if err != nil {
		t.Fatalf("s.Sign(message) err = %v, want nil", err)
	}
	if !bytes.Equal(got, wantSig) {
		t.Errorf("s.Sign(message) = %x, want %x", got, wantSig)
	}
}

func TestSignerKeyManagerPrimitiveWithInvalidInputFails(t *testing.T) {
	km, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}
	validPrivKey, err := makeValidRSAPKCS1Key()
	if err != nil {
		t.Fatalf("makeValidRSAPKCS1Key() err = %v, want nil", err)
	}
	serializedValidPrivate, err := proto.Marshal(validPrivKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	if _, err := km.Primitive(serializedValidPrivate); err != nil {
		t.Fatalf("Primitive(serializedValidPrivate) err = %v, want nil", err)
	}
	type testCase struct {
		name string
		key  *rsassapkcs1pb.RsaSsaPkcs1PrivateKey
	}
	for _, tc := range []testCase{
		{
			name: "empty key",
			key:  &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{},
		},
		{
			name: "nil key",
			key:  nil,
		},
		{
			name: "invalid version",
			key: &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
				Version:   validPrivKey.GetVersion() + 1,
				PublicKey: validPrivKey.GetPublicKey(),
				D:         validPrivKey.GetD(),
				P:         validPrivKey.GetP(),
				Q:         validPrivKey.GetQ(),
				Dp:        validPrivKey.GetDp(),
				Dq:        validPrivKey.GetDq(),
				Crt:       validPrivKey.GetCrt(),
			},
		},
		{
			name: "invalid hash algorithm ",
			key: &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
				Version: validPrivKey.GetVersion(),
				PublicKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
					Version: validPrivKey.GetPublicKey().GetVersion(),
					E:       validPrivKey.GetPublicKey().GetE(),
					N:       validPrivKey.GetPublicKey().GetN(),
					Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
						HashType: cpb.HashType_SHA224,
					},
				},
				D:   validPrivKey.GetD(),
				P:   validPrivKey.GetP(),
				Q:   validPrivKey.GetQ(),
				Dp:  validPrivKey.GetDp(),
				Dq:  validPrivKey.GetDq(),
				Crt: validPrivKey.GetCrt(),
			},
		},
		{
			name: "public key params field unset",
			key: &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
				Version: validPrivKey.GetVersion(),
				PublicKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
					Version: validPrivKey.GetPublicKey().GetVersion(),
					E:       validPrivKey.GetPublicKey().GetE(),
					N:       validPrivKey.GetPublicKey().GetN(),
					Params:  nil,
				},
				D:   validPrivKey.GetD(),
				P:   validPrivKey.GetP(),
				Q:   validPrivKey.GetQ(),
				Dp:  validPrivKey.GetDp(),
				Dq:  validPrivKey.GetDq(),
				Crt: validPrivKey.GetCrt(),
			},
		},
		{
			name: "invalid modulus",
			key: &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
				Version: validPrivKey.GetVersion(),
				PublicKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
					Version: validPrivKey.GetPublicKey().GetVersion(),
					E:       validPrivKey.GetPublicKey().GetE(),
					N:       []byte{3, 4, 5},
					Params:  validPrivKey.GetPublicKey().GetParams(),
				},
				D:   validPrivKey.GetD(),
				P:   validPrivKey.GetP(),
				Q:   validPrivKey.GetQ(),
				Dp:  validPrivKey.GetDp(),
				Dq:  validPrivKey.GetDq(),
				Crt: validPrivKey.GetCrt(),
			},
		},
		{
			name: "invalid public key exponent",
			key: &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
				Version: validPrivKey.GetVersion(),
				PublicKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
					Version: validPrivKey.GetPublicKey().GetVersion(),
					E:       []byte{0x06},
					N:       validPrivKey.GetPublicKey().GetN(),
					Params:  validPrivKey.GetPublicKey().GetParams(),
				},
				D:   validPrivKey.GetD(),
				P:   validPrivKey.GetP(),
				Q:   validPrivKey.GetQ(),
				Dp:  validPrivKey.GetDp(),
				Dq:  validPrivKey.GetDq(),
				Crt: validPrivKey.GetCrt(),
			},
		},
		{
			name: "invalid private key D value",
			key: &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
				Version:   validPrivKey.GetVersion(),
				PublicKey: validPrivKey.GetPublicKey(),
				D:         nil,
				P:         validPrivKey.GetP(),
				Q:         validPrivKey.GetQ(),
				Dp:        validPrivKey.GetDp(),
				Dq:        validPrivKey.GetDq(),
				Crt:       validPrivKey.GetCrt(),
			},
		},

		{
			name: "invalid private key P value",
			key: &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
				Version:   validPrivKey.GetVersion(),
				PublicKey: validPrivKey.GetPublicKey(),
				D:         validPrivKey.GetD(),
				P:         nil,
				Q:         validPrivKey.GetQ(),
				Dp:        validPrivKey.GetDp(),
				Dq:        validPrivKey.GetDq(),
				Crt:       validPrivKey.GetCrt(),
			},
		},
		{
			name: "invalid private key Q value",
			key: &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
				Version:   validPrivKey.GetVersion(),
				PublicKey: validPrivKey.GetPublicKey(),
				D:         validPrivKey.GetD(),
				P:         validPrivKey.GetP(),
				Q:         nil,
				Dp:        validPrivKey.GetDp(),
				Dq:        validPrivKey.GetDq(),
				Crt:       validPrivKey.GetCrt(),
			},
		},
		{
			name: "invalid precomputed Dp values in private key",
			key: &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
				Version:   validPrivKey.GetVersion(),
				PublicKey: validPrivKey.GetPublicKey(),
				D:         validPrivKey.GetD(),
				P:         validPrivKey.GetP(),
				Q:         validPrivKey.GetQ(),
				Dp:        nil,
				Dq:        validPrivKey.GetDq(),
				Crt:       validPrivKey.GetCrt(),
			},
		},
		{
			name: "invalid precomputed Dq values in private key",
			key: &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
				Version:   validPrivKey.GetVersion(),
				PublicKey: validPrivKey.GetPublicKey(),
				D:         validPrivKey.GetD(),
				P:         validPrivKey.GetP(),
				Q:         validPrivKey.GetQ(),
				Dp:        validPrivKey.GetDp(),
				Dq:        nil,
				Crt:       validPrivKey.GetCrt(),
			},
		},
		{
			name: "invalid precomputed Crt values in private key",
			key: &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
				Version:   validPrivKey.GetVersion(),
				PublicKey: validPrivKey.GetPublicKey(),
				D:         validPrivKey.GetD(),
				P:         validPrivKey.GetP(),
				Q:         validPrivKey.GetQ(),
				Dp:        validPrivKey.GetDp(),
				Dq:        validPrivKey.GetDq(),
				Crt:       nil,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serializedKey, err := proto.Marshal(tc.key)
			if err != nil {
				t.Fatalf("proto.Marshal() err = %v, want nil", err)
			}
			if _, err := km.Primitive(serializedKey); err == nil {
				t.Errorf("Primitive() err = nil, want error")
			}
			if _, err := km.(registry.PrivateKeyManager).PublicKeyData(serializedKey); err == nil {
				t.Errorf("PublicKeyData() err = nil, want error")
			}
		})
	}
}

func TestSignerKeyManagerPrimitiveWithNilOrEmptyKeyFails(t *testing.T) {
	km, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}
	for _, serializedKey := range [][]byte{nil, []byte{}} {
		if _, err := km.Primitive(serializedKey); err == nil {
			t.Errorf("km.Primitive() err = nil, want error")
		}
	}
}

func TestSignerKeyManagerPrimitiveWithCorruptedKeyFails(t *testing.T) {
	km, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}
	corruptedPrivKey, err := makeValidRSAPKCS1Key()
	if err != nil {
		t.Fatalf("makeValidRSAPKCS1Key() err = %v, want nil", err)
	}
	corruptedPrivKey.P[5] = byte(uint8(corruptedPrivKey.P[5] + 1))
	corruptedPrivKey.P[10] = byte(uint8(corruptedPrivKey.P[10] + 1))
	serializedCorruptedPrivate, err := proto.Marshal(corruptedPrivKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	if _, err := km.Primitive(serializedCorruptedPrivate); err == nil {
		t.Errorf("Primitive() err = nil, want error")
	}
}

func TestSignerKeyManagerPrimitiveNewKey(t *testing.T) {
	km, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}
	validPrivKey, err := makeValidRSAPKCS1Key()
	if err != nil {
		t.Fatalf("makeValidRSAPKCS1Key() err = %v, want nil", err)
	}
	keyFormat := &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
		Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
			HashType: cpb.HashType_SHA256,
		},
		ModulusSizeInBits: 3072,
		PublicExponent:    []byte{0x01, 0x00, 0x01},
	}
	serializedFormat, err := proto.Marshal(keyFormat)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	m, err := km.NewKey(serializedFormat)
	if err != nil {
		t.Fatalf("NewKey() err = %v, want nil", err)
	}
	privKey, ok := m.(*rsassapkcs1pb.RsaSsaPkcs1PrivateKey)
	if !ok {
		t.Fatalf("privateKey is not a RsaSsaPkcs1PrivateKey")
	}
	if privKey.GetVersion() != validPrivKey.GetVersion() {
		t.Errorf("GetVersion() = %d, want %d", privKey.GetVersion(), validPrivKey.GetVersion())
	}
	wantPubKey := validPrivKey.GetPublicKey()
	gotPubKey := privKey.GetPublicKey()
	if gotPubKey.GetParams().GetHashType() != wantPubKey.GetParams().GetHashType() {
		t.Errorf("GetHashType() = %v, want %v", gotPubKey.GetParams().GetHashType(), wantPubKey.GetParams().GetHashType())
	}
	if !cmp.Equal(gotPubKey.GetE(), wantPubKey.GetE()) {
		t.Errorf("GetE() = %v, want %v", gotPubKey.GetE(), wantPubKey.GetE())
	}
	gotModSize := new(big.Int).SetBytes(gotPubKey.GetN()).BitLen()
	if gotModSize != 3072 {
		t.Errorf("Modulus Size = %d, want %d", gotModSize, 3072)
	}
}

func TestSignerKeyManagerPrimitiveNewKeyWithInvalidInputFails(t *testing.T) {
	type testCase struct {
		name   string
		format *rsassapkcs1pb.RsaSsaPkcs1KeyFormat
	}
	km, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}
	for _, tc := range []testCase{
		{
			name:   "empty format",
			format: &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{},
		},
		{
			name: "invalid hash",
			format: &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				ModulusSizeInBits: 2048,
				PublicExponent:    []byte{0x01, 0x00, 0x01},
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: cpb.HashType_SHA224,
				},
			},
		},
		{
			name: "invalid public exponent",
			format: &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				ModulusSizeInBits: 2048,
				PublicExponent:    []byte{0x01},
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: cpb.HashType_SHA256,
				},
			},
		},
		{
			name: "invalid modulus size",
			format: &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				ModulusSizeInBits: 1024,
				PublicExponent:    []byte{0x01},
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: cpb.HashType_SHA256,
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serializedFormat, err := proto.Marshal(tc.format)
			if err != nil {
				t.Fatalf("proto.Marshal() err = %v, want nil", err)
			}
			if _, err := km.NewKey(serializedFormat); err == nil {
				t.Fatalf("NewKey() err = nil, want error")
			}
		})
	}
}

func TestSignerKeyManagerPrimitiveNewKeyData(t *testing.T) {
	km, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}
	keyFormat := &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
		ModulusSizeInBits: 2048,
		PublicExponent:    []byte{0x01, 0x00, 0x01},
		Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
			HashType: cpb.HashType_SHA256,
		},
	}
	serializedFormat, err := proto.Marshal(keyFormat)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	keyData, err := km.NewKeyData(serializedFormat)
	if err != nil {
		t.Fatalf("NewKeyData() err = %v, want nil", err)
	}
	if keyData.GetTypeUrl() != privateKeyTypeURL {
		t.Errorf("GetTypeUrl() = %v, want %v", keyData.GetTypeUrl(), privateKeyTypeURL)
	}
	if keyData.GetKeyMaterialType() != tinkpb.KeyData_ASYMMETRIC_PRIVATE {
		t.Errorf("GetKeyMaterialType() = %v, want %v", keyData.GetKeyMaterialType(), tinkpb.KeyData_ASYMMETRIC_PRIVATE)
	}
	if _, err := km.Primitive(keyData.GetValue()); err != nil {
		t.Errorf("Primitive() err = %v, want nil", err)
	}
}

func TestSignerKeyManagerPrimitiveNISTTestVectors(t *testing.T) {
	km, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}
	for _, tc := range nistPKCS1TestVectors {
		t.Run(tc.name, func(t *testing.T) {
			key, err := tc.ToProtoKey()
			if err != nil {
				t.Fatalf("tc.ToProtoKey() err = %v, want nil", err)
			}
			serializedKey, err := proto.Marshal(key)
			if err != nil {
				t.Fatalf("proto.Marshal() err = %v, want nil", err)
			}
			p, err := km.Primitive(serializedKey)
			if err != nil {
				t.Fatalf("km.Primitive() err = %v, want nil", err)
			}
			msg, err := hex.DecodeString(tc.msg)
			if err != nil {
				t.Fatalf("hex.DecodeString(tc.msg) err = %v, want nil", err)
			}
			signer, ok := p.(tink.Signer)
			if !ok {
				t.Fatalf("primitive isn't a Tink.Signer")
			}
			sig, err := signer.Sign(msg)
			if err != nil {
				t.Fatalf("p.(tink.Signer).Sign(msg) err = %v, want nil", err)
			}
			gotSig := hex.EncodeToString(sig)
			if !cmp.Equal(gotSig, tc.sig) {
				t.Errorf("Sign() = %q, want %q", gotSig, tc.sig)
			}
		})
	}
}
