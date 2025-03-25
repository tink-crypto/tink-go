// Copyright 2025 Google LLC
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

package hpke_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/hybrid/ecies"
	"github.com/tink-crypto/tink-go/v2/hybrid/hpke"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	hpkepb "github.com/tink-crypto/tink-go/v2/proto/hpke_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

type testParams struct{}

func (p *testParams) HasIDRequirement() bool { return true }

func (p *testParams) Equal(params key.Parameters) bool { return true }

type testKey struct{}

func (k *testKey) Parameters() key.Parameters { return &testParams{} }

func (k *testKey) Equal(other key.Key) bool { return true }

func (k *testKey) IDRequirement() (uint32, bool) { return 123, true }

func TestSerializePublicKeyFails(t *testing.T) {
	for _, tc := range []struct {
		name      string
		publicKey key.Key
	}{
		{
			name:      "nil key",
			publicKey: nil,
		},
		{
			name:      "invalid public key",
			publicKey: &hpke.PublicKey{},
		},
		{
			name:      "incorrect key type",
			publicKey: &testKey{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.SerializeKey(tc.publicKey); err == nil {
				t.Errorf("protoserialization.SerializeKey(%v) err = nil, want non-nil", tc.publicKey)
			}
		})
	}
}

type protoSerializationTestCase struct {
	name                    string
	publicKey               *hpke.PublicKey
	publicKeySerialization  *protoserialization.KeySerialization
	privateKey              *hpke.PrivateKey
	privateKeySerialization *protoserialization.KeySerialization
}

func mustCreateKeySerialization(t *testing.T, url string, keyMaterialType tinkpb.KeyData_KeyMaterialType, keyMessage proto.Message, outputPrefixType tinkpb.OutputPrefixType, idRequirement uint32) *protoserialization.KeySerialization {
	t.Helper()
	serializedKey, err := proto.Marshal(keyMessage)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", keyMessage, err)
	}
	keyData := &tinkpb.KeyData{
		TypeUrl:         url,
		Value:           serializedKey,
		KeyMaterialType: keyMaterialType,
	}
	ks, err := protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
	if err != nil {
		t.Fatalf("protoserialization.NewKeySerialization(%v, %v, %v) err = %v, want nil", keyData, outputPrefixType, idRequirement, err)
	}
	return ks
}

func mustCreatePrivateKey(t *testing.T, privateKeyBytes []byte, publicKey *hpke.PublicKey) *hpke.PrivateKey {
	t.Helper()
	secretData := secretdata.NewBytesFromData(privateKeyBytes, insecuresecretdataaccess.Token{})
	pk, err := hpke.NewPrivateKeyFromPublicKey(secretData, publicKey)
	if err != nil {
		t.Fatalf("hpke.NewPrivateKeyFromPublicKey(%x, %v) err = %v, want nil", secretData, publicKey, err)
	}
	return pk
}

func mustCreateTestCases(t *testing.T) []protoSerializationTestCase {
	t.Helper()

	p256PublicKeyBytes := mustHexDecode(t, p256SHA256PublicKeyBytesHex)
	p256PrivateKeyBytes := mustHexDecode(t, p256SHA256PrivateKeyBytesHex)
	p384PublicKeyBytes := mustHexDecode(t, p384PublicKeyBytesHex)
	p384PrivateKeyBytes := mustHexDecode(t, p384PrivateKeyBytesHex)
	p521PublicKeyBytes := mustHexDecode(t, p521SHA512PublicKeyBytesHex)
	p521PrivateKeyBytes := mustHexDecode(t, p521SHA512PrivateKeyBytesHex)
	x25519PublicKeyBytes := mustHexDecode(t, x25519PublicKeyBytesHex)
	x25519PrivateKeyBytes := mustHexDecode(t, x25519PrivateKeyBytesHex)

	testCases := []protoSerializationTestCase{}
	for _, aeadID := range []struct {
		enumAEADID  hpke.AEADID
		protoAEADID hpkepb.HpkeAead
	}{
		{hpke.AES128GCM, hpkepb.HpkeAead_AES_128_GCM},
		{hpke.AES256GCM, hpkepb.HpkeAead_AES_256_GCM},
		{hpke.ChaCha20Poly1305, hpkepb.HpkeAead_CHACHA20_POLY1305},
	} {
		for _, kdfID := range []struct {
			enumKDFID  hpke.KDFID
			protoKDFID hpkepb.HpkeKdf
		}{
			{hpke.HKDFSHA256, hpkepb.HpkeKdf_HKDF_SHA256},
			{hpke.HKDFSHA384, hpkepb.HpkeKdf_HKDF_SHA384},
			{hpke.HKDFSHA512, hpkepb.HpkeKdf_HKDF_SHA512},
		} {
			for _, variant := range []struct {
				enumVariant  hpke.Variant
				protoVariant tinkpb.OutputPrefixType
			}{
				{hpke.VariantTink, tinkpb.OutputPrefixType_TINK},
				{hpke.VariantCrunchy, tinkpb.OutputPrefixType_CRUNCHY},
				{hpke.VariantNoPrefix, tinkpb.OutputPrefixType_RAW},
			} {
				idRequirement := uint32(0x01020304)
				if variant.enumVariant == hpke.VariantNoPrefix {
					idRequirement = 0
				}
				for _, kemIDAndKeyBytes := range []struct {
					enumKEMID       hpke.KEMID
					protoKEMID      hpkepb.HpkeKem
					publicKeyBytes  []byte
					privateKeyBytes []byte
				}{
					{hpke.DHKEM_P256_HKDF_SHA256, hpkepb.HpkeKem_DHKEM_P256_HKDF_SHA256, p256PublicKeyBytes, p256PrivateKeyBytes},
					{hpke.DHKEM_P384_HKDF_SHA384, hpkepb.HpkeKem_DHKEM_P384_HKDF_SHA384, p384PublicKeyBytes, p384PrivateKeyBytes},
					{hpke.DHKEM_P521_HKDF_SHA512, hpkepb.HpkeKem_DHKEM_P521_HKDF_SHA512, p521PublicKeyBytes, p521PrivateKeyBytes},
					{hpke.DHKEM_X25519_HKDF_SHA256, hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256, x25519PublicKeyBytes, x25519PrivateKeyBytes},
				} {
					publicKey := mustCreatePublicKey(t, kemIDAndKeyBytes.publicKeyBytes, idRequirement, mustCreateParameters(t, hpke.ParametersOpts{
						KEMID:   kemIDAndKeyBytes.enumKEMID,
						KDFID:   kdfID.enumKDFID,
						AEADID:  aeadID.enumAEADID,
						Variant: variant.enumVariant,
					}))
					protoPublicKey := &hpkepb.HpkePublicKey{
						Version: 0,
						Params: &hpkepb.HpkeParams{
							Kem:  kemIDAndKeyBytes.protoKEMID,
							Kdf:  kdfID.protoKDFID,
							Aead: aeadID.protoAEADID,
						},
						PublicKey: kemIDAndKeyBytes.publicKeyBytes,
					}
					publicKeySerialization := mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.HpkePublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
						protoPublicKey, variant.protoVariant, idRequirement)
					privateKey := mustCreatePrivateKey(t, kemIDAndKeyBytes.privateKeyBytes, publicKey)
					privateKeySerialization := mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.HpkePrivateKey", tinkpb.KeyData_ASYMMETRIC_PRIVATE,
						&hpkepb.HpkePrivateKey{
							Version:    0,
							PublicKey:  protoPublicKey,
							PrivateKey: kemIDAndKeyBytes.privateKeyBytes,
						}, variant.protoVariant, idRequirement)
					testCases = append(testCases, protoSerializationTestCase{
						name:                    fmt.Sprintf("%s-%s-%s-%s", kemIDAndKeyBytes.enumKEMID, kdfID.enumKDFID, aeadID.enumAEADID, variant.enumVariant),
						publicKey:               publicKey,
						publicKeySerialization:  publicKeySerialization,
						privateKey:              privateKey,
						privateKeySerialization: privateKeySerialization,
					})
				}
			}
		}
	}
	return testCases
}

func TestSerializePublicKey(t *testing.T) {
	for _, tc := range mustCreateTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.SerializeKey(tc.publicKey)
			if err != nil {
				t.Fatalf("protoserialization.SerializeKey(%v) err = %v, want nil", tc.publicKey, err)
			}
			if diff := cmp.Diff(got, tc.publicKeySerialization); diff != "" {
				t.Errorf("protoserialization.SerializeKey(%v) returned unexpected diff (-want +got):\n%s", tc.publicKey, diff)
			}
		})
	}
}

func TestParsePublicKeyFails(t *testing.T) {
	p256SHA256PublicKeyBytes := mustHexDecode(t, p256SHA256PublicKeyBytesHex)
	for _, tc := range []struct {
		name                   string
		publicKeySerialization *protoserialization.KeySerialization
	}{
		{
			name: "invalid key material type",
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.HpkePublicKey", tinkpb.KeyData_ASYMMETRIC_PRIVATE,
				&hpkepb.HpkePublicKey{
					Version: 0,
					Params: &hpkepb.HpkeParams{
						Kem:  hpkepb.HpkeKem_DHKEM_P256_HKDF_SHA256,
						Kdf:  hpkepb.HpkeKdf_HKDF_SHA256,
						Aead: hpkepb.HpkeAead_AES_256_GCM,
					},
					PublicKey: p256SHA256PublicKeyBytes,
				}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid key version",
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.HpkePublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
				&hpkepb.HpkePublicKey{
					Version: 1,
					Params: &hpkepb.HpkeParams{
						Kem:  hpkepb.HpkeKem_DHKEM_P256_HKDF_SHA256,
						Kdf:  hpkepb.HpkeKdf_HKDF_SHA256,
						Aead: hpkepb.HpkeAead_AES_256_GCM,
					},
					PublicKey: p256SHA256PublicKeyBytes,
				}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid NIST point for curve type",
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.HpkePublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
				&hpkepb.HpkePublicKey{
					Version: 0,
					Params: &hpkepb.HpkeParams{
						Kem:  hpkepb.HpkeKem_DHKEM_P384_HKDF_SHA384,
						Kdf:  hpkepb.HpkeKdf_HKDF_SHA256,
						Aead: hpkepb.HpkeAead_AES_256_GCM,
					},
					PublicKey: p256SHA256PublicKeyBytes,
				}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid KEM",
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.HpkePublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
				&hpkepb.HpkePublicKey{
					Version: 0,
					Params: &hpkepb.HpkeParams{
						Kem:  hpkepb.HpkeKem_KEM_UNKNOWN,
						Kdf:  hpkepb.HpkeKdf_HKDF_SHA256,
						Aead: hpkepb.HpkeAead_AES_256_GCM,
					},
					PublicKey: p256SHA256PublicKeyBytes,
				}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid KDF",
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.HpkePublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
				&hpkepb.HpkePublicKey{
					Version: 0,
					Params: &hpkepb.HpkeParams{
						Kem:  hpkepb.HpkeKem_DHKEM_P256_HKDF_SHA256,
						Kdf:  hpkepb.HpkeKdf_KDF_UNKNOWN,
						Aead: hpkepb.HpkeAead_AES_256_GCM,
					},
					PublicKey: p256SHA256PublicKeyBytes,
				}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid AEAD",
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.HpkePublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
				&hpkepb.HpkePublicKey{
					Version: 0,
					Params: &hpkepb.HpkeParams{
						Kem:  hpkepb.HpkeKem_DHKEM_P256_HKDF_SHA256,
						Kdf:  hpkepb.HpkeKdf_HKDF_SHA256,
						Aead: hpkepb.HpkeAead_AEAD_UNKNOWN,
					},
					PublicKey: p256SHA256PublicKeyBytes,
				}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid public key value",
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.HpkePublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
				&hpkepb.HpkePublicKey{
					Version: 0,
					Params: &hpkepb.HpkeParams{
						Kem:  hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
						Kdf:  hpkepb.HpkeKdf_HKDF_SHA256,
						Aead: hpkepb.HpkeAead_AES_256_GCM,
					},
					PublicKey: []byte("invalid"),
				}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid prefix type",
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.HpkePublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
				&hpkepb.HpkePublicKey{
					Version: 0,
					Params: &hpkepb.HpkeParams{
						Kem:  hpkepb.HpkeKem_DHKEM_P256_HKDF_SHA256,
						Kdf:  hpkepb.HpkeKdf_HKDF_SHA256,
						Aead: hpkepb.HpkeAead_AES_256_GCM,
					},
					PublicKey: p256SHA256PublicKeyBytes,
				}, tinkpb.OutputPrefixType_UNKNOWN_PREFIX, 0),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.ParseKey(tc.publicKeySerialization); err == nil {
				t.Errorf("protoserialization.ParseKey(%v) err = nil, want error", tc.publicKeySerialization)
			}
		})
	}
}

func TestParsePublicKey(t *testing.T) {
	for _, tc := range mustCreateTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.ParseKey(tc.publicKeySerialization)
			if err != nil {
				t.Fatalf("protoserialization.ParseKey(%v) err = %v, want nil", tc.publicKeySerialization, err)
			}
			if diff := cmp.Diff(got, tc.publicKey); diff != "" {
				t.Errorf("protoserialization.ParseKey(%v) returned unexpected diff (-want +got):\n%s", tc.publicKey, diff)
			}
		})
	}
}

func TestSerializePrivateKey(t *testing.T) {
	for _, tc := range mustCreateTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.SerializeKey(tc.privateKey)
			if err != nil {
				t.Fatalf("protoserialization.SerializeKey(%v) err = %v, want nil", tc.privateKey, err)
			}
			if diff := cmp.Diff(got, tc.privateKeySerialization, protocmp.Transform()); diff != "" {
				t.Errorf("protoserialization.SerializeKey(%v) returned unexpected diff (-want +got):\n%s", tc.privateKey, diff)
			}
		})
	}
}

func TestSerializePrivateKeyFails(t *testing.T) {
	for _, tc := range []struct {
		name       string
		privateKey key.Key
	}{
		{
			name:       "nil key",
			privateKey: nil,
		},
		{
			name:       "invalid private key",
			privateKey: &ecies.PrivateKey{},
		},
		{
			name:       "incorrect key type",
			privateKey: &testKey{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.SerializeKey(tc.privateKey); err == nil {
				t.Errorf("protoserialization.SerializeKey(%v) err = nil, want non-nil", tc.privateKey)
			}
		})
	}
}

func TestParsePrivateKey(t *testing.T) {
	for _, tc := range mustCreateTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.ParseKey(tc.privateKeySerialization)
			if err != nil {
				t.Fatalf("protoserialization.ParseKey(%v) err = %v, want nil", tc.privateKeySerialization, err)
			}
			if diff := cmp.Diff(got, tc.privateKey); diff != "" {
				t.Errorf("protoserialization.ParseKey(%v) returned unexpected diff (-want +got):\n%s", tc.publicKey, diff)
			}
		})
	}
}

func TestParsePrivateKeyFails(t *testing.T) {
	x25519PublicKeyBytes := mustHexDecode(t, x25519PublicKeyBytesHex)
	x25519PrivateKeyBytes := mustHexDecode(t, x25519PrivateKeyBytesHex)
	p256SHA256PublicKeyBytes := mustHexDecode(t, p256SHA256PublicKeyBytesHex)
	p256SHA256PrivateKeyBytes := mustHexDecode(t, p256SHA256PrivateKeyBytesHex)

	for _, tc := range []struct {
		name                    string
		privateKeySerialization *protoserialization.KeySerialization
	}{
		{
			name: "invalid proto private key",
			privateKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.HpkePrivateKey", tinkpb.KeyData_ASYMMETRIC_PRIVATE,
				&hpkepb.HpkePrivateKey{
					Version: 0,
					PublicKey: &hpkepb.HpkePublicKey{
						Version: 0,
						Params: &hpkepb.HpkeParams{
							Kem:  hpkepb.HpkeKem_DHKEM_P256_HKDF_SHA256,
							Kdf:  hpkepb.HpkeKdf_HKDF_SHA256,
							Aead: hpkepb.HpkeAead_AES_256_GCM,
						},
						PublicKey: p256SHA256PublicKeyBytes,
					},
					PrivateKey: x25519PrivateKeyBytes,
				}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid public key",
			privateKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.HpkePrivateKey", tinkpb.KeyData_ASYMMETRIC_PRIVATE,
				&hpkepb.HpkePrivateKey{
					Version: 0,
					PublicKey: &hpkepb.HpkePublicKey{
						Version: 0,
						Params: &hpkepb.HpkeParams{
							Kem:  hpkepb.HpkeKem_DHKEM_P256_HKDF_SHA256,
							Kdf:  hpkepb.HpkeKdf_HKDF_SHA256,
							Aead: hpkepb.HpkeAead_AES_256_GCM,
						},
						PublicKey: x25519PublicKeyBytes,
					},
					PrivateKey: p256SHA256PrivateKeyBytes,
				}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid private key version",
			privateKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.HpkePrivateKey", tinkpb.KeyData_ASYMMETRIC_PRIVATE,
				&hpkepb.HpkePrivateKey{
					Version: 1,
					PublicKey: &hpkepb.HpkePublicKey{
						Version: 0,
						Params: &hpkepb.HpkeParams{
							Kem:  hpkepb.HpkeKem_DHKEM_P256_HKDF_SHA256,
							Kdf:  hpkepb.HpkeKdf_HKDF_SHA256,
							Aead: hpkepb.HpkeAead_AES_256_GCM,
						},
						PublicKey: p256SHA256PublicKeyBytes,
					},
					PrivateKey: p256SHA256PrivateKeyBytes,
				}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid X25519 private key bytes",
			privateKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.HpkePrivateKey", tinkpb.KeyData_ASYMMETRIC_PRIVATE,
				&hpkepb.HpkePrivateKey{
					Version: 0,
					PublicKey: &hpkepb.HpkePublicKey{
						Version: 0,
						Params: &hpkepb.HpkeParams{
							Kem:  hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
							Kdf:  hpkepb.HpkeKdf_HKDF_SHA256,
							Aead: hpkepb.HpkeAead_AES_256_GCM,
						},
						PublicKey: x25519PublicKeyBytes,
					},
					PrivateKey: x25519PrivateKeyBytes[:len(x25519PrivateKeyBytes)-1], // Only checks the scalar length.
				}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid NIST private key bytes",
			privateKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.HpkePrivateKey", tinkpb.KeyData_ASYMMETRIC_PRIVATE,
				&hpkepb.HpkePrivateKey{
					Version: 0,
					PublicKey: &hpkepb.HpkePublicKey{
						Version: 0,
						Params: &hpkepb.HpkeParams{
							Kem:  hpkepb.HpkeKem_DHKEM_P256_HKDF_SHA256,
							Kdf:  hpkepb.HpkeKdf_HKDF_SHA256,
							Aead: hpkepb.HpkeAead_AES_256_GCM,
						},
						PublicKey: p256SHA256PublicKeyBytes,
					},
					PrivateKey: func() []byte {
						key := slices.Clone(p256SHA256PrivateKeyBytes)
						key[0] ^= 1
						return key
					}(),
				}, tinkpb.OutputPrefixType_RAW, 0),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.ParseKey(tc.privateKeySerialization); err == nil {
				t.Errorf("protoserialization.ParseKey(%v) err = nil, want error", tc.privateKeySerialization)
			}
		})
	}
}

type parametersSerializationTestCase struct {
	name        string
	parameters  *hpke.Parameters
	keyTemplate *tinkpb.KeyTemplate
}

func mustCreateKeyTemplate(t *testing.T, outputPrefixType tinkpb.OutputPrefixType, kem hpkepb.HpkeKem, kdf hpkepb.HpkeKdf, aead hpkepb.HpkeAead) *tinkpb.KeyTemplate {
	t.Helper()
	format := &hpkepb.HpkeKeyFormat{
		Params: &hpkepb.HpkeParams{
			Kem:  kem,
			Kdf:  kdf,
			Aead: aead,
		},
	}
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", format, err)
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          "type.googleapis.com/google.crypto.tink.HpkePrivateKey",
		OutputPrefixType: outputPrefixType,
		Value:            serializedFormat,
	}
}

func mustCreateParametersTestParameters(t *testing.T) []parametersSerializationTestCase {
	t.Helper()
	tcs := []parametersSerializationTestCase{}
	for _, aeadID := range []struct {
		enumAEADID  hpke.AEADID
		protoAEADID hpkepb.HpkeAead
	}{
		{hpke.AES128GCM, hpkepb.HpkeAead_AES_128_GCM},
		{hpke.AES256GCM, hpkepb.HpkeAead_AES_256_GCM},
		{hpke.ChaCha20Poly1305, hpkepb.HpkeAead_CHACHA20_POLY1305},
	} {
		for _, kdfID := range []struct {
			enumKDFID  hpke.KDFID
			protoKDFID hpkepb.HpkeKdf
		}{
			{hpke.HKDFSHA256, hpkepb.HpkeKdf_HKDF_SHA256},
			{hpke.HKDFSHA384, hpkepb.HpkeKdf_HKDF_SHA384},
			{hpke.HKDFSHA512, hpkepb.HpkeKdf_HKDF_SHA512},
		} {
			for _, variant := range []struct {
				enumVariant  hpke.Variant
				protoVariant tinkpb.OutputPrefixType
			}{
				{hpke.VariantTink, tinkpb.OutputPrefixType_TINK},
				{hpke.VariantCrunchy, tinkpb.OutputPrefixType_CRUNCHY},
				{hpke.VariantNoPrefix, tinkpb.OutputPrefixType_RAW},
			} {
				for _, kemIDAndKeyBytes := range []struct {
					enumKEMID  hpke.KEMID
					protoKEMID hpkepb.HpkeKem
				}{
					{hpke.DHKEM_P256_HKDF_SHA256, hpkepb.HpkeKem_DHKEM_P256_HKDF_SHA256},
					{hpke.DHKEM_P384_HKDF_SHA384, hpkepb.HpkeKem_DHKEM_P384_HKDF_SHA384},
					{hpke.DHKEM_P521_HKDF_SHA512, hpkepb.HpkeKem_DHKEM_P521_HKDF_SHA512},
					{hpke.DHKEM_X25519_HKDF_SHA256, hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256},
				} {
					tcs = append(tcs, parametersSerializationTestCase{
						name: fmt.Sprintf("%s-%s-%s-%s", kemIDAndKeyBytes.enumKEMID, kdfID.enumKDFID, aeadID.enumAEADID, variant.enumVariant),
						parameters: mustCreateParameters(t, hpke.ParametersOpts{
							KEMID:   kemIDAndKeyBytes.enumKEMID,
							KDFID:   kdfID.enumKDFID,
							AEADID:  aeadID.enumAEADID,
							Variant: variant.enumVariant,
						}),
						keyTemplate: mustCreateKeyTemplate(t, variant.protoVariant, kemIDAndKeyBytes.protoKEMID, kdfID.protoKDFID, aeadID.protoAEADID),
					})
				}
			}
		}
	}
	return tcs
}

func TestParseParameters(t *testing.T) {
	for _, tc := range mustCreateParametersTestParameters(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.ParseParameters(tc.keyTemplate)
			if err != nil {
				t.Fatalf("protoserialization.ParseParameters(%v) err = %v, want nil", tc.keyTemplate, err)
			}
			if diff := cmp.Diff(got, tc.parameters); diff != "" {
				t.Errorf("protoserialization.ParseParameters(%v) returned unexpected diff (-want +got):\n%s", tc.parameters, diff)
			}
		})
	}
}

func TestParseParametersFails(t *testing.T) {
	for _, tc := range []struct {
		name        string
		keyTemplate *tinkpb.KeyTemplate
	}{
		{
			name:        "unknown output prefix type",
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_UNKNOWN_PREFIX, hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256, hpkepb.HpkeKdf_HKDF_SHA256, hpkepb.HpkeAead_AES_256_GCM),
		},
		{
			name:        "unknown KEM",
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_TINK, hpkepb.HpkeKem_KEM_UNKNOWN, hpkepb.HpkeKdf_HKDF_SHA256, hpkepb.HpkeAead_AES_256_GCM),
		},
		{
			name:        "unknown KDF",
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_TINK, hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256, hpkepb.HpkeKdf_KDF_UNKNOWN, hpkepb.HpkeAead_AES_256_GCM),
		},
		{
			name:        "unknown AEAD",
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_TINK, hpkepb.HpkeKem_DHKEM_P256_HKDF_SHA256, hpkepb.HpkeKdf_HKDF_SHA256, hpkepb.HpkeAead_AEAD_UNKNOWN),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.ParseParameters(tc.keyTemplate); err == nil {
				t.Errorf("protoserialization.ParseParameters(%v) err = nil, want non-nil", tc.keyTemplate)
			}
		})
	}
}

func TestSerializeParameters(t *testing.T) {
	for _, tc := range mustCreateParametersTestParameters(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.SerializeParameters(tc.parameters)
			if err != nil {
				t.Fatalf("protoserialization.SerializeParameters(%v) err = %v, want nil", tc.parameters, err)
			}
			if diff := cmp.Diff(got, tc.keyTemplate, protocmp.Transform()); diff != "" {
				t.Errorf("protoserialization.SerializeParameters(%v) returned unexpected diff (-want +got):\n%s", tc.keyTemplate, diff)
			}
		})
	}
}
