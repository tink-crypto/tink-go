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

package rsassapss_test

import (
	"math/big"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	_ "github.com/tink-crypto/tink-go/v2/signature/rsassapss" // register rsassapss key managers
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/tink"
	cpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	rsppb "github.com/tink-crypto/tink-go/v2/proto/rsa_ssa_pss_go_proto"
	tpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	privateKeyTypeURL = "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey"
	privateKeyVersion = 0
)

func TestSignerKeyManagerKeyManagerDoesSupport(t *testing.T) {
	skm, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", err, privateKeyTypeURL)
	}
	if !skm.DoesSupport(privateKeyTypeURL) {
		t.Errorf("DoesSupport(%q) err = false, want true", privateKeyTypeURL)
	}
	if skm.DoesSupport("fake.type.url") {
		t.Errorf("DoesSupport(%q) err = true, want false", "fake.type.url")
	}
}

func TestSignerKeyManagerKeyManagerTypeURL(t *testing.T) {
	skm, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", err, privateKeyTypeURL)
	}
	if skm.TypeURL() != privateKeyTypeURL {
		t.Errorf("TypeURL() = %q, want %q", skm.TypeURL(), privateKeyTypeURL)
	}
}

func TestSignerKeyManagerGetPrimitive(t *testing.T) {
	skm, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", err, privateKeyTypeURL)
	}
	privKey, err := makeValidRSAPSSKey()
	if err != nil {
		t.Fatalf("makeValidRSAPSSKey() err = %v, want nil", err)
	}
	serializedPrivate, err := proto.Marshal(privKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	p, err := skm.Primitive(serializedPrivate)
	if err != nil {
		t.Fatalf("Primitive() err = %v, want nil", err)
	}
	signer := p.(tink.Signer)
	vkm, err := registry.GetKeyManager(publicKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", err, publicKeyTypeURL)
	}
	serializedPublic, err := proto.Marshal(privKey.GetPublicKey())
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	p, err = vkm.Primitive(serializedPublic)
	if err != nil {
		t.Fatalf("Primitive() err = %v, want nil", err)
	}
	verifier := p.(tink.Verifier)
	data := random.GetRandomBytes(80)
	signature, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("Sign() err = %v, want nil", err)
	}
	if err := verifier.Verify(signature, data); err != nil {
		t.Fatalf("Verify() err = %v, want nil", err)
	}
}

func mergePrivPub(priv *rsppb.RsaSsaPssPrivateKey, pub *rsppb.RsaSsaPssPublicKey) *rsppb.RsaSsaPssPrivateKey {
	return &rsppb.RsaSsaPssPrivateKey{
		Version:   priv.GetVersion(),
		PublicKey: pub,
		D:         priv.GetD(),
		P:         priv.GetP(),
		Q:         priv.GetQ(),
		Dp:        priv.GetDp(),
		Dq:        priv.GetDq(),
		Crt:       priv.GetCrt(),
	}
}

func TestSignerKeyManagerGetPrimitiveWithInvalidInput(t *testing.T) {
	type testCase struct {
		tag     string
		privKey *rsppb.RsaSsaPssPrivateKey
	}
	skm, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", err, privateKeyTypeURL)
	}
	validPrivKey, err := makeValidRSAPSSKey()
	if err != nil {
		t.Fatalf("makeValidRSAPSSKey() err = %v, want nil", err)
	}
	for _, tc := range []testCase{
		{
			tag:     "empty private key",
			privKey: &rsppb.RsaSsaPssPrivateKey{},
		},
		{
			tag: "invalid private key version",
			privKey: &rsppb.RsaSsaPssPrivateKey{
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
			tag: "invalid private key D",
			privKey: &rsppb.RsaSsaPssPrivateKey{
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
			tag: "invalid private key P",
			privKey: &rsppb.RsaSsaPssPrivateKey{
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
			tag: "invalid private key Q",
			privKey: &rsppb.RsaSsaPssPrivateKey{
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
			tag: "invalid private key Dp",
			privKey: &rsppb.RsaSsaPssPrivateKey{
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
			tag: "invalid private key Dq",
			privKey: &rsppb.RsaSsaPssPrivateKey{
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
			tag: "invalid private key Crt",
			privKey: &rsppb.RsaSsaPssPrivateKey{
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
		{
			tag:     "empty public key",
			privKey: mergePrivPub(validPrivKey, &rsppb.RsaSsaPssPublicKey{}),
		},
		{
			tag: "nil public key params",
			privKey: mergePrivPub(
				validPrivKey,
				&rsppb.RsaSsaPssPublicKey{
					Version: validPrivKey.GetPublicKey().GetVersion(),
					Params:  nil,
					N:       validPrivKey.GetPublicKey().GetN(),
					E:       validPrivKey.GetPublicKey().GetE(),
				}),
		},
		{
			tag: "invalid public key version",
			privKey: mergePrivPub(
				validPrivKey,
				&rsppb.RsaSsaPssPublicKey{
					Version: validPrivKey.GetPublicKey().GetVersion() + 1,
					Params:  validPrivKey.GetPublicKey().GetParams(),
					N:       validPrivKey.GetPublicKey().GetN(),
					E:       validPrivKey.GetPublicKey().GetE(),
				}),
		},
		{
			tag: "different sig and mgf1 hash functions",
			privKey: mergePrivPub(
				validPrivKey,
				&rsppb.RsaSsaPssPublicKey{
					Version: validPrivKey.GetPublicKey().GetVersion(),
					Params: &rsppb.RsaSsaPssParams{
						SigHash:    cpb.HashType_SHA256,
						Mgf1Hash:   cpb.HashType_SHA384,
						SaltLength: validPrivKey.GetPublicKey().GetParams().GetSaltLength(),
					},
					N: validPrivKey.GetPublicKey().GetN(),
					E: validPrivKey.GetPublicKey().GetE(),
				}),
		},
		{
			tag: "negative salt length",
			privKey: mergePrivPub(
				validPrivKey,
				&rsppb.RsaSsaPssPublicKey{
					Version: validPrivKey.GetPublicKey().GetVersion(),
					Params: &rsppb.RsaSsaPssParams{
						SigHash:    validPrivKey.GetPublicKey().GetParams().GetSigHash(),
						Mgf1Hash:   validPrivKey.GetPublicKey().GetParams().GetMgf1Hash(),
						SaltLength: -1,
					},
					N: validPrivKey.GetPublicKey().GetN(),
					E: validPrivKey.GetPublicKey().GetE(),
				}),
		},
		{
			tag: "invalid hash function",
			privKey: mergePrivPub(
				validPrivKey,
				&rsppb.RsaSsaPssPublicKey{
					Version: validPrivKey.GetPublicKey().GetVersion(),
					Params: &rsppb.RsaSsaPssParams{
						SigHash:    cpb.HashType_UNKNOWN_HASH,
						Mgf1Hash:   cpb.HashType_UNKNOWN_HASH,
						SaltLength: validPrivKey.GetPublicKey().GetParams().GetSaltLength(),
					},
					N: validPrivKey.GetPublicKey().GetN(),
					E: validPrivKey.GetPublicKey().GetE(),
				}),
		},
		{
			tag: "unsafe hash function",
			privKey: mergePrivPub(
				validPrivKey,
				&rsppb.RsaSsaPssPublicKey{
					Version: validPrivKey.GetPublicKey().GetVersion(),
					Params: &rsppb.RsaSsaPssParams{
						SigHash:    cpb.HashType_SHA1,
						Mgf1Hash:   cpb.HashType_SHA1,
						SaltLength: validPrivKey.GetPublicKey().GetParams().GetSaltLength(),
					},
					N: validPrivKey.GetPublicKey().GetN(),
					E: validPrivKey.GetPublicKey().GetE(),
				}),
		},
		{
			tag: "invalid modulus",
			privKey: mergePrivPub(
				validPrivKey,
				&rsppb.RsaSsaPssPublicKey{
					Version: validPrivKey.GetPublicKey().GetVersion(),
					Params:  validPrivKey.GetPublicKey().GetParams(),
					N:       []byte{0x00},
					E:       validPrivKey.GetPublicKey().GetE(),
				}),
		},
		{
			tag: "invalid exponent",
			privKey: mergePrivPub(
				validPrivKey,
				&rsppb.RsaSsaPssPublicKey{
					Version: validPrivKey.GetPublicKey().GetVersion(),
					Params:  validPrivKey.GetPublicKey().GetParams(),
					N:       validPrivKey.GetPublicKey().GetN(),
					E:       []byte{0x01},
				}),
		},
		{
			tag: "exponent larger than 64 bits",
			privKey: mergePrivPub(
				validPrivKey,
				&rsppb.RsaSsaPssPublicKey{
					Version: validPrivKey.GetPublicKey().GetVersion(),
					Params:  validPrivKey.GetPublicKey().GetParams(),
					N:       validPrivKey.GetPublicKey().GetN(),
					E:       random.GetRandomBytes(32),
				}),
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			serializedPrivKey, err := proto.Marshal(tc.privKey)
			if err != nil {
				t.Fatalf("proto.Marshal() err = %v, want nil", err)
			}
			if _, err := skm.Primitive(serializedPrivKey); err == nil {
				t.Errorf("Primitive() err = nil, want error")
			}
			if _, err := skm.(registry.PrivateKeyManager).PublicKeyData(serializedPrivKey); err == nil {
				t.Errorf("PublicKeyData() err = nil, want error")
			}
		})
	}
}

func TestSignerKeyManagerGetPrimitiveWithCorruptedPrivateKey(t *testing.T) {
	skm, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", err, privateKeyTypeURL)
	}
	validPrivKey, err := makeValidRSAPSSKey()
	if err != nil {
		t.Fatalf("makeValidRSAPSSKey() err = %v, want nil", err)
	}
	corruptedPrivKey := validPrivKey
	corruptedPrivKey.P[5] <<= 1
	corruptedPrivKey.P[20] <<= 1
	serializedPrivKey, err := proto.Marshal(corruptedPrivKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	if _, err := skm.Primitive(serializedPrivKey); err == nil {
		t.Errorf("Primitive() err = nil, want error")
	}
}

func TestSignerKeyManagerNewKey(t *testing.T) {
	keyFormat := &rsppb.RsaSsaPssKeyFormat{
		Params: &rsppb.RsaSsaPssParams{
			SigHash:    cpb.HashType_SHA256,
			Mgf1Hash:   cpb.HashType_SHA256,
			SaltLength: 32,
		},
		ModulusSizeInBits: 3072,
		PublicExponent:    []byte{0x01, 0x00, 0x01},
	}
	serializedKeyFormat, err := proto.Marshal(keyFormat)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	skm, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", err, privateKeyTypeURL)
	}
	key, err := skm.NewKey(serializedKeyFormat)
	if err != nil {
		t.Fatalf("NewKey() err = %v, want nil", err)
	}
	privKey, ok := key.(*rsppb.RsaSsaPssPrivateKey)
	if !ok {
		t.Fatalf("key isn't a *rsppb.RsaSsaPssPrivateKey")
	}
	if privKey.GetVersion() != privateKeyVersion {
		t.Errorf("privKey.GetVersion() = %d, want %d", privKey.GetVersion(), privateKeyVersion)
	}
	if privKey.GetD() == nil {
		t.Error("GetD() == nil, want []byte{}")
	}
	if privKey.GetP() == nil {
		t.Error("GetP() == nil, want []byte{}")
	}
	if privKey.GetQ() == nil {
		t.Error("GetQ() == nil, want []byte{}")
	}
	if privKey.GetDp() == nil {
		t.Error("GetDp() == nil, want []byte{}")
	}
	if privKey.GetDq() == nil {
		t.Error("GetDq() == nil, want []byte{}")
	}
	if privKey.GetCrt() == nil {
		t.Error("GetCrt() == nil, want []byte{}")
	}
	pubKey := privKey.GetPublicKey()
	if !cmp.Equal(pubKey.GetE(), keyFormat.GetPublicExponent()) {
		t.Errorf("GetE() = %v, want %v", pubKey.GetE(), keyFormat.GetPublicExponent())
	}
	n := uint32(new(big.Int).SetBytes(pubKey.GetN()).BitLen())
	if !cmp.Equal(n, keyFormat.GetModulusSizeInBits()) {
		t.Errorf("Modulus size in bits = %q, want %q", n, keyFormat.GetModulusSizeInBits())
	}
	if !cmp.Equal(pubKey.GetParams(), keyFormat.GetParams(), protocmp.Transform()) {
		t.Errorf("GetParams() = %v, want %v", pubKey.GetParams(), keyFormat.GetParams())
	}
}

func TestSignerKeyManagerNewKeyData(t *testing.T) {
	keyFormat := &rsppb.RsaSsaPssKeyFormat{
		Params: &rsppb.RsaSsaPssParams{
			SigHash:    cpb.HashType_SHA256,
			Mgf1Hash:   cpb.HashType_SHA256,
			SaltLength: 32,
		},
		ModulusSizeInBits: 3072,
		PublicExponent:    []byte{0x01, 0x00, 0x01},
	}
	serializedKeyFormat, err := proto.Marshal(keyFormat)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	skm, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", err, privateKeyTypeURL)
	}
	vkm, err := registry.GetKeyManager(publicKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", err, publicKeyTypeURL)
	}
	keyData, err := skm.NewKeyData(serializedKeyFormat)
	if err != nil {
		t.Fatalf("skm.NewKeyData() err = %v, want nil", err)
	}
	if keyData.GetKeyMaterialType() != tpb.KeyData_ASYMMETRIC_PRIVATE {
		t.Errorf("keyData.GetKeyMaterialType() = %v, want %v", keyData.GetKeyMaterialType(), tpb.KeyData_ASYMMETRIC_PRIVATE)
	}
	if keyData.GetTypeUrl() != privateKeyTypeURL {
		t.Errorf("keyData.GetTypeUrl() = %q, want %q", keyData.GetTypeUrl(), privateKeyTypeURL)
	}
	// Creating a primitive does a self key test which signs and verifies data.
	s, err := skm.Primitive(keyData.GetValue())
	if err != nil {
		t.Fatalf("Primitive() err = %v, want nil", err)
	}
	signer, ok := s.(tink.Signer)
	if !ok {
		t.Fatal("Primitive() return type isn't a tink.Signer")
	}
	data := random.GetRandomBytes(50)
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("signer.Sign() err = %v, want nil", err)
	}
	pubKeyData, err := skm.(registry.PrivateKeyManager).PublicKeyData(keyData.GetValue())
	if err != nil {
		t.Fatalf("PublicKeyData() err = %v, want nil", err)
	}
	v, err := vkm.Primitive(pubKeyData.GetValue())
	if err != nil {
		t.Fatalf("Primitive() err = %v, want nil", err)
	}
	verifier, ok := v.(tink.Verifier)
	if !ok {
		t.Fatal("Primitive() return type isn't a tink.Verifier")
	}
	if err := verifier.Verify(sig, data); err != nil {
		t.Fatalf("verifier.Verify() err = %v, want nil", err)
	}
}

func TestSignerKeyManagerNewKeyFailsWithInvalidFormat(t *testing.T) {
	type testCase struct {
		tag       string
		keyFormat *rsppb.RsaSsaPssKeyFormat
	}
	skm, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", err, privateKeyTypeURL)
	}
	validKeyFormat := &rsppb.RsaSsaPssKeyFormat{
		Params: &rsppb.RsaSsaPssParams{
			SigHash:    cpb.HashType_SHA256,
			Mgf1Hash:   cpb.HashType_SHA256,
			SaltLength: 32,
		},
		ModulusSizeInBits: 3072,
		PublicExponent:    []byte{0x01, 0x00, 0x01},
	}
	serializedKeyFormat, err := proto.Marshal(validKeyFormat)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	if _, err := skm.NewKeyData(serializedKeyFormat); err != nil {
		t.Fatalf("NewKeyData() err = %v, want nil", err)
	}
	for _, tc := range []testCase{
		{
			tag: "nil params",
			keyFormat: &rsppb.RsaSsaPssKeyFormat{
				Params:            nil,
				ModulusSizeInBits: validKeyFormat.GetModulusSizeInBits(),
				PublicExponent:    validKeyFormat.GetPublicExponent(),
			},
		},
		{
			tag: "unsafe hash function",
			keyFormat: &rsppb.RsaSsaPssKeyFormat{
				Params: &rsppb.RsaSsaPssParams{
					SigHash:    cpb.HashType_SHA224,
					Mgf1Hash:   cpb.HashType_SHA224,
					SaltLength: validKeyFormat.GetParams().GetSaltLength(),
				},
				ModulusSizeInBits: validKeyFormat.GetModulusSizeInBits(),
				PublicExponent:    validKeyFormat.GetPublicExponent(),
			},
		},
		{
			tag: "different signature and mgf1 hash function",
			keyFormat: &rsppb.RsaSsaPssKeyFormat{
				Params: &rsppb.RsaSsaPssParams{
					SigHash:    cpb.HashType_SHA384,
					Mgf1Hash:   cpb.HashType_SHA512,
					SaltLength: validKeyFormat.GetParams().GetSaltLength(),
				},
				ModulusSizeInBits: validKeyFormat.GetModulusSizeInBits(),
				PublicExponent:    validKeyFormat.GetPublicExponent(),
			},
		},
		{
			tag: "negative salt length",
			keyFormat: &rsppb.RsaSsaPssKeyFormat{
				Params: &rsppb.RsaSsaPssParams{
					SigHash:    validKeyFormat.GetParams().GetSigHash(),
					Mgf1Hash:   validKeyFormat.GetParams().GetMgf1Hash(),
					SaltLength: -1,
				},
				ModulusSizeInBits: validKeyFormat.GetModulusSizeInBits(),
				PublicExponent:    validKeyFormat.GetPublicExponent(),
			},
		},
		{
			tag: "insecure modulus size",
			keyFormat: &rsppb.RsaSsaPssKeyFormat{
				Params:            validKeyFormat.GetParams(),
				ModulusSizeInBits: 2047,
				PublicExponent:    validKeyFormat.GetPublicExponent(),
			},
		},
		{
			tag: "invalid public exponent",
			keyFormat: &rsppb.RsaSsaPssKeyFormat{
				Params:            validKeyFormat.GetParams(),
				ModulusSizeInBits: validKeyFormat.GetModulusSizeInBits(),
				PublicExponent:    []byte{0x00, 0x00, 0x03},
			},
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			serializedKeyFormat, err := proto.Marshal(tc.keyFormat)
			if err != nil {
				t.Fatalf("proto.Marshal() err = %v, want nil", err)
			}
			if _, err := skm.NewKey(serializedKeyFormat); err == nil {
				t.Fatalf("NewKey() err = nil, want error")
			}
			if _, err := skm.NewKeyData(serializedKeyFormat); err == nil {
				t.Fatalf("NewKeyData() err = nil, want error")
			}
		})
	}
}

func TestSignerKeyManagerPublicKeyInvalidInput(t *testing.T) {
	for _, tc := range []struct {
		name              string
		serializedPrivKey []byte
	}{
		{
			name:              "nil private key",
			serializedPrivKey: nil,
		},
		{
			name:              "empty private key",
			serializedPrivKey: []byte{},
		},
		{
			name:              "invalid private key bytes",
			serializedPrivKey: []byte("1234"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			skm, err := registry.GetKeyManager(privateKeyTypeURL)
			if err != nil {
				t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", err, privateKeyTypeURL)
			}
			if _, err := skm.(registry.PrivateKeyManager).PublicKeyData(tc.serializedPrivKey); err == nil {
				t.Errorf("PublicKeyData() err = nil, want error")
			}
		})
	}
}

func TestSignerKeyManagerPublicKeyData(t *testing.T) {
	skm, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", err, privateKeyTypeURL)
	}
	vkm, err := registry.GetKeyManager(publicKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", err, publicKeyTypeURL)
	}
	validPrivKey, err := makeValidRSAPSSKey()
	if err != nil {
		t.Fatalf("makeValidRSAPSSKey() err = %v, want nil", err)
	}
	serializedPrivKey, err := proto.Marshal(validPrivKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	pubKeyData, err := skm.(registry.PrivateKeyManager).PublicKeyData(serializedPrivKey)
	if err != nil {
		t.Fatalf("PublicKeyData() err = %v, want nil", err)
	}
	if pubKeyData.GetKeyMaterialType() != tpb.KeyData_ASYMMETRIC_PUBLIC {
		t.Errorf("GetKeyMaterialType() = %v, want %v", pubKeyData.GetKeyMaterialType(), tpb.KeyData_ASYMMETRIC_PUBLIC)
	}
	if pubKeyData.GetTypeUrl() != publicKeyTypeURL {
		t.Errorf("GetTypeUrl() = %q, want %q", pubKeyData.GetTypeUrl(), publicKeyTypeURL)
	}
	if _, err := vkm.Primitive(pubKeyData.GetValue()); err != nil {
		t.Fatalf("vkm.Primitive() err = %v, want nil", err)
	}
}
