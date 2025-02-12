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

package ecies_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/hybrid/ecies"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/signature"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	eciespb "github.com/tink-crypto/tink-go/v2/proto/ecies_aead_hkdf_go_proto"
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
			publicKey: &ecies.PublicKey{},
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

type protoSerializationTestCase struct {
	name                   string
	publicKey              *ecies.PublicKey
	publicKeySerialization *protoserialization.KeySerialization
	noLeadingZeroes        bool
}

func mustCreateTestCases(t *testing.T) []protoSerializationTestCase {
	t.Helper()
	demParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() err = %v, want nil", err)
	}

	// Add a leading 0x00 byte to the coordinates for compatibility with other
	// Tink implementations (see b/264525021).
	x25519PublicKeyBytes := mustHexDecode(t, x25519PublicKeyBytesHex)
	p256PublicKeyBytes := mustHexDecode(t, p256SHA256PublicKeyBytesHex)
	p256PublicKeyX := make([]byte, 33)
	p256PublicKeyY := make([]byte, 33)
	copy(p256PublicKeyX[1:], p256PublicKeyBytes[1:33])
	copy(p256PublicKeyY[1:], p256PublicKeyBytes[33:])

	p384PrivKey, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ecdh.P384().GenerateKey() err = %v, want nil", err)
	}
	p384PublicKeyBytes := p384PrivKey.PublicKey().Bytes()
	p384PublicKeyX := make([]byte, 49)
	p384PublicKeyY := make([]byte, 49)
	copy(p384PublicKeyX[1:], p384PublicKeyBytes[1:49])
	copy(p384PublicKeyY[1:], p384PublicKeyBytes[49:])

	p521PublicKeyBytes := mustHexDecode(t, p521SHA512PublicKeyBytesHex)
	p521PublicKeyX := make([]byte, 67)
	p521PublicKeyY := make([]byte, 67)
	copy(p521PublicKeyX[1:], p521PublicKeyBytes[1:67])
	copy(p521PublicKeyY[1:], p521PublicKeyBytes[67:])

	testCases := []protoSerializationTestCase{}

	for _, hashType := range []struct {
		enumHashType  ecies.HashType
		protoHashType commonpb.HashType
	}{
		{ecies.SHA1, commonpb.HashType_SHA1},
		{ecies.SHA224, commonpb.HashType_SHA224},
		{ecies.SHA256, commonpb.HashType_SHA256},
		{ecies.SHA384, commonpb.HashType_SHA384},
		{ecies.SHA512, commonpb.HashType_SHA512},
	} {
		for _, variantAndPrefix := range []struct {
			variant ecies.Variant
			prefix  tinkpb.OutputPrefixType
		}{
			{ecies.VariantTink, tinkpb.OutputPrefixType_TINK},
			{ecies.VariantCrunchy, tinkpb.OutputPrefixType_CRUNCHY},
			{ecies.VariantNoPrefix, tinkpb.OutputPrefixType_RAW},
		} {
			idRequirement := uint32(0x01020304)
			if variantAndPrefix.variant == ecies.VariantNoPrefix {
				idRequirement = 0
			}
			for _, nistCurve := range []struct {
				enumCurveType  ecies.CurveType
				protoCurveType commonpb.EllipticCurveType
				x, y           []byte
				encodedPoint   []byte
			}{
				{ecies.NISTP256, commonpb.EllipticCurveType_NIST_P256, p256PublicKeyX, p256PublicKeyY, p256PublicKeyBytes},
				{ecies.NISTP384, commonpb.EllipticCurveType_NIST_P384, p384PublicKeyX, p384PublicKeyY, p384PublicKeyBytes},
				{ecies.NISTP521, commonpb.EllipticCurveType_NIST_P521, p521PublicKeyX, p521PublicKeyY, p521PublicKeyBytes},
			} {
				for _, pointFormat := range []struct {
					enumPointFormat  ecies.PointFormat
					protoPointFormat commonpb.EcPointFormat
				}{
					{ecies.CompressedPointFormat, commonpb.EcPointFormat_COMPRESSED},
					{ecies.UncompressedPointFormat, commonpb.EcPointFormat_UNCOMPRESSED},
					{ecies.LegacyUncompressedPointFormat, commonpb.EcPointFormat_DO_NOT_USE_CRUNCHY_UNCOMPRESSED},
				} {
					testCases = append(testCases, protoSerializationTestCase{
						name: fmt.Sprintf("%s-%s-%s-%s", nistCurve.enumCurveType, hashType.enumHashType, variantAndPrefix.variant, pointFormat.enumPointFormat),
						publicKey: mustCreatePublicKey(t, nistCurve.encodedPoint, idRequirement, mustCreateParameters(t, ecies.ParametersOpts{
							CurveType:            nistCurve.enumCurveType,
							HashType:             hashType.enumHashType,
							NISTCurvePointFormat: pointFormat.enumPointFormat,
							DEMParameters:        demParams,
							Variant:              variantAndPrefix.variant,
							Salt:                 []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
						})),
						publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
							&eciespb.EciesAeadHkdfPublicKey{
								Params: &eciespb.EciesAeadHkdfParams{
									KemParams: &eciespb.EciesHkdfKemParams{
										CurveType:    nistCurve.protoCurveType,
										HkdfHashType: hashType.protoHashType,
										HkdfSalt:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
									},
									DemParams: &eciespb.EciesAeadDemParams{
										AeadDem: aead.AES256GCMNoPrefixKeyTemplate(),
									},
									EcPointFormat: pointFormat.protoPointFormat,
								},
								X: nistCurve.x,
								Y: nistCurve.y,
							}, variantAndPrefix.prefix, idRequirement),
					})
				}
			}
			testCases = append(testCases, protoSerializationTestCase{
				name: fmt.Sprintf("%s-%s-%s-%s", ecies.X25519, hashType.enumHashType, variantAndPrefix.variant, ecies.UnspecifiedPointFormat),
				publicKey: mustCreatePublicKey(t, x25519PublicKeyBytes, idRequirement, mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.X25519,
					HashType:             hashType.enumHashType,
					NISTCurvePointFormat: ecies.UnspecifiedPointFormat,
					DEMParameters:        demParams,
					Variant:              variantAndPrefix.variant,
					Salt:                 []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
				})),
				publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
					&eciespb.EciesAeadHkdfPublicKey{
						Params: &eciespb.EciesAeadHkdfParams{
							KemParams: &eciespb.EciesHkdfKemParams{
								CurveType:    commonpb.EllipticCurveType_CURVE25519,
								HkdfHashType: hashType.protoHashType,
								HkdfSalt:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
							},
							DemParams: &eciespb.EciesAeadDemParams{
								AeadDem: aead.AES256GCMNoPrefixKeyTemplate(),
							},
							EcPointFormat: commonpb.EcPointFormat_COMPRESSED, // This is unspecified only for X25519, but always serialized as COMPRESSED.
						},
						X: x25519PublicKeyBytes,
					}, variantAndPrefix.prefix, idRequirement),
			})
		}
	}
	return testCases
}

func TestSerializePublicKey(t *testing.T) {
	for _, tc := range mustCreateTestCases(t) {
		if tc.noLeadingZeroes {
			// Produced serialization always has leading zeroes.
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.SerializeKey(tc.publicKey)
			if err != nil {
				t.Fatalf("protoserialization.SerializeKey(%v) err = %v, want nil", tc.publicKey, err)
			}
			if diff := cmp.Diff(got, tc.publicKeySerialization, protocmp.Transform()); diff != "" {
				t.Errorf("protoserialization.SerializeKey(%v) returned unexpected diff (-want +got):\n%s", tc.publicKey, diff)
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
	x25519PublicKeyBytes := mustHexDecode(t, x25519PublicKeyBytesHex)
	// Additional test case to make sure OutputPrefixType_LEGACY is parsed as VariantCrunchy.
	publicKeySerialization := mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
		&eciespb.EciesAeadHkdfPublicKey{
			Params: &eciespb.EciesAeadHkdfParams{
				KemParams: &eciespb.EciesHkdfKemParams{
					CurveType:    commonpb.EllipticCurveType_CURVE25519,
					HkdfHashType: commonpb.HashType_SHA256,
					HkdfSalt:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
				},
				DemParams: &eciespb.EciesAeadDemParams{
					AeadDem: aead.AES256GCMNoPrefixKeyTemplate(),
				},
				EcPointFormat: commonpb.EcPointFormat_COMPRESSED,
			},
			X: x25519PublicKeyBytes,
		}, tinkpb.OutputPrefixType_LEGACY, 1234)
	got, err := protoserialization.ParseKey(publicKeySerialization)
	if err != nil {
		t.Fatalf("protoserialization.ParseKey(%v) err = %v, want nil", publicKeySerialization, err)
	}
	if got.Parameters().(*ecies.Parameters).Variant() != ecies.VariantCrunchy {
		t.Errorf("got.Parameters().(*ecies.Parameters).Variant() = %v, want %v", got.Parameters().(*ecies.Parameters).Variant(), ecies.VariantCrunchy)
	}
}

func TestParsePublicKeyFails(t *testing.T) {
	x25519PublicKeyBytes := mustHexDecode(t, x25519PublicKeyBytesHex)
	p256SHA256PublicKeyBytes := mustHexDecode(t, p256SHA256PublicKeyBytesHex)
	p256SHA256PublicKeyX := make([]byte, 33)
	p256SHA256PublicKeyY := make([]byte, 33)
	copy(p256SHA256PublicKeyX[1:], p256SHA256PublicKeyBytes[1:33])
	copy(p256SHA256PublicKeyY[1:], p256SHA256PublicKeyBytes[33:])

	for _, tc := range []struct {
		name                   string
		publicKeySerialization *protoserialization.KeySerialization
	}{
		{
			name: "invalid key material type",
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey", tinkpb.KeyData_ASYMMETRIC_PRIVATE,
				&eciespb.EciesAeadHkdfPublicKey{
					Params: &eciespb.EciesAeadHkdfParams{
						KemParams: &eciespb.EciesHkdfKemParams{
							CurveType:    commonpb.EllipticCurveType_NIST_P256,
							HkdfHashType: commonpb.HashType_SHA256,
							HkdfSalt:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
						},
						DemParams: &eciespb.EciesAeadDemParams{
							AeadDem: aead.AES256GCMNoPrefixKeyTemplate(),
						},
						EcPointFormat: commonpb.EcPointFormat_UNCOMPRESSED,
					},
					X: p256SHA256PublicKeyX,
					Y: p256SHA256PublicKeyY,
				}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid key version",
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
				&eciespb.EciesAeadHkdfPublicKey{
					Version: 1,
					Params: &eciespb.EciesAeadHkdfParams{
						KemParams: &eciespb.EciesHkdfKemParams{
							CurveType:    commonpb.EllipticCurveType_NIST_P256,
							HkdfHashType: commonpb.HashType_SHA256,
							HkdfSalt:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
						},
						DemParams: &eciespb.EciesAeadDemParams{
							AeadDem: aead.AES256GCMNoPrefixKeyTemplate(),
						},
						EcPointFormat: commonpb.EcPointFormat_UNCOMPRESSED,
					},
					X: p256SHA256PublicKeyX,
					Y: p256SHA256PublicKeyY,
				}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid point for curve type - NIST",
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
				&eciespb.EciesAeadHkdfPublicKey{
					Params: &eciespb.EciesAeadHkdfParams{
						KemParams: &eciespb.EciesHkdfKemParams{
							CurveType:    commonpb.EllipticCurveType_NIST_P384,
							HkdfHashType: commonpb.HashType_SHA256,
							HkdfSalt:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
						},
						DemParams: &eciespb.EciesAeadDemParams{
							AeadDem: aead.AES256GCMNoPrefixKeyTemplate(),
						},
						EcPointFormat: commonpb.EcPointFormat_UNCOMPRESSED,
					},
					X: p256SHA256PublicKeyX,
					Y: p256SHA256PublicKeyY,
				}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid point format for curve type - CURVE25519",
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
				&eciespb.EciesAeadHkdfPublicKey{
					Params: &eciespb.EciesAeadHkdfParams{
						KemParams: &eciespb.EciesHkdfKemParams{
							CurveType:    commonpb.EllipticCurveType_CURVE25519,
							HkdfHashType: commonpb.HashType_SHA256,
							HkdfSalt:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
						},
						DemParams: &eciespb.EciesAeadDemParams{
							AeadDem: aead.AES256GCMNoPrefixKeyTemplate(),
						},
						EcPointFormat: commonpb.EcPointFormat_UNCOMPRESSED,
					},
					X: x25519PublicKeyBytes,
				}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid hash type",
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
				&eciespb.EciesAeadHkdfPublicKey{
					Params: &eciespb.EciesAeadHkdfParams{
						KemParams: &eciespb.EciesHkdfKemParams{
							CurveType:    commonpb.EllipticCurveType_NIST_P256,
							HkdfHashType: commonpb.HashType_UNKNOWN_HASH,
							HkdfSalt:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
						},
						DemParams: &eciespb.EciesAeadDemParams{
							AeadDem: aead.AES256GCMNoPrefixKeyTemplate(),
						},
						EcPointFormat: commonpb.EcPointFormat_UNCOMPRESSED,
					},
					X: p256SHA256PublicKeyX,
					Y: p256SHA256PublicKeyY,
				}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid DEM params",
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
				&eciespb.EciesAeadHkdfPublicKey{
					Params: &eciespb.EciesAeadHkdfParams{
						KemParams: &eciespb.EciesHkdfKemParams{
							CurveType:    commonpb.EllipticCurveType_NIST_P256,
							HkdfHashType: commonpb.HashType_SHA256,
							HkdfSalt:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
						},
						DemParams: &eciespb.EciesAeadDemParams{
							AeadDem: signature.ECDSAP256KeyTemplate(),
						},
						EcPointFormat: commonpb.EcPointFormat_UNCOMPRESSED,
					},
					X: p256SHA256PublicKeyX,
					Y: p256SHA256PublicKeyY,
				}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid compression format",
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
				&eciespb.EciesAeadHkdfPublicKey{
					Params: &eciespb.EciesAeadHkdfParams{
						KemParams: &eciespb.EciesHkdfKemParams{
							CurveType:    commonpb.EllipticCurveType_CURVE25519,
							HkdfHashType: commonpb.HashType_SHA256,
							HkdfSalt:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
						},
						DemParams: &eciespb.EciesAeadDemParams{
							AeadDem: aead.AES256GCMNoPrefixKeyTemplate(),
						},
						EcPointFormat: commonpb.EcPointFormat_UNCOMPRESSED,
					},
					X: x25519PublicKeyBytes,
				}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid X25519 public key",
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
				&eciespb.EciesAeadHkdfPublicKey{
					Params: &eciespb.EciesAeadHkdfParams{
						KemParams: &eciespb.EciesHkdfKemParams{
							CurveType:    commonpb.EllipticCurveType_CURVE25519,
							HkdfHashType: commonpb.HashType_SHA256,
							HkdfSalt:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
						},
						DemParams: &eciespb.EciesAeadDemParams{
							AeadDem: aead.AES256GCMNoPrefixKeyTemplate(),
						},
						EcPointFormat: commonpb.EcPointFormat_COMPRESSED,
					},
					X: []byte("invalid"),
				}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid NIST x coordinate",
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
				&eciespb.EciesAeadHkdfPublicKey{
					Params: &eciespb.EciesAeadHkdfParams{
						KemParams: &eciespb.EciesHkdfKemParams{
							CurveType:    commonpb.EllipticCurveType_NIST_P256,
							HkdfHashType: commonpb.HashType_SHA256,
							HkdfSalt:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
						},
						DemParams: &eciespb.EciesAeadDemParams{
							AeadDem: aead.AES256GCMNoPrefixKeyTemplate(),
						},
						EcPointFormat: commonpb.EcPointFormat_COMPRESSED,
					},
					X: func() []byte {
						x := bytes.Clone(p256SHA256PublicKeyX)
						x[0] ^= 1
						return x
					}(),
					Y: p256SHA256PublicKeyY,
				}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid NIST y coordinate",
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
				&eciespb.EciesAeadHkdfPublicKey{
					Params: &eciespb.EciesAeadHkdfParams{
						KemParams: &eciespb.EciesHkdfKemParams{
							CurveType:    commonpb.EllipticCurveType_NIST_P256,
							HkdfHashType: commonpb.HashType_SHA256,
							HkdfSalt:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
						},
						DemParams: &eciespb.EciesAeadDemParams{
							AeadDem: aead.AES256GCMNoPrefixKeyTemplate(),
						},
						EcPointFormat: commonpb.EcPointFormat_COMPRESSED,
					},
					X: p256SHA256PublicKeyX,
					Y: func() []byte {
						y := bytes.Clone(p256SHA256PublicKeyY)
						y[0] ^= 1
						return y
					}(),
				}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid prefix type",
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
				&eciespb.EciesAeadHkdfPublicKey{
					Params: &eciespb.EciesAeadHkdfParams{
						KemParams: &eciespb.EciesHkdfKemParams{
							CurveType:    commonpb.EllipticCurveType_NIST_P256,
							HkdfHashType: commonpb.HashType_SHA256,
							HkdfSalt:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
						},
						DemParams: &eciespb.EciesAeadDemParams{
							AeadDem: aead.AES256GCMNoPrefixKeyTemplate(),
						},
						EcPointFormat: commonpb.EcPointFormat_COMPRESSED,
					},
					X: p256SHA256PublicKeyX,
					Y: p256SHA256PublicKeyY,
				}, tinkpb.OutputPrefixType_UNKNOWN_PREFIX, 1234),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.ParseKey(tc.publicKeySerialization); err == nil {
				t.Errorf("protoserialization.ParseKey(%v) err = nil, want error", tc.publicKeySerialization)
			}
		})
	}
}
