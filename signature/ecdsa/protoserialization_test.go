// Copyright 2024 Google LLC
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

package ecdsa

import (
	"encoding/hex"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	ecdsapb "github.com/tink-crypto/tink-go/v2/proto/ecdsa_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func newKeySerialization(t *testing.T, keyData *tinkpb.KeyData, outputPrefixType tinkpb.OutputPrefixType, idRequirement uint32) *protoserialization.KeySerialization {
	t.Helper()
	ks, err := protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
	if err != nil {
		t.Fatalf("protoserialization.NewKeySerialization(%v, %v, %v) err = %v, want nil", keyData, outputPrefixType, idRequirement, err)
	}
	return ks
}

const (
	// Taken from
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/ecdsa_secp256r1_sha256_test.json#L22
	pubKeyXP256Hex      = "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838"
	pubKeyYP256Hex      = "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e"
	uncompressedP256Hex = "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e"

	// Taken from
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/ecdsa_secp384r1_sha384_test.json#L22
	pubKeyXP384Hex      = "2da57dda1089276a543f9ffdac0bff0d976cad71eb7280e7d9bfd9fee4bdb2f20f47ff888274389772d98cc5752138aa"
	pubKeyYP384Hex      = "4b6d054d69dcf3e25ec49df870715e34883b1836197d76f8ad962e78f6571bbc7407b0d6091f9e4d88f014274406174f"
	uncompressedP384Hex = "042da57dda1089276a543f9ffdac0bff0d976cad71eb7280e7d9bfd9fee4bdb2f20f47ff888274389772d98cc5752138aa4b6d054d69dcf3e25ec49df870715e34883b1836197d76f8ad962e78f6571bbc7407b0d6091f9e4d88f014274406174f"

	// Taken from
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/ecdsa_secp521r1_sha3_512_test.json#L21
	pubKeyXP521Hex      = "5c6457ec088d532f482093965ae53ccd07e556ed59e2af945cd8c7a95c1c644f8a56a8a8a3cd77392ddd861e8a924dac99c69069093bd52a52fa6c56004a074508"
	pubKeyYP521Hex      = "7878d6d42e4b4dd1e9c0696cb3e19f63033c3db4e60d473259b3ebe079aaf0a986ee6177f8217a78c68b813f7e149a4e56fd9562c07fed3d895942d7d101cb83f6"
	uncompressedP521Hex = "04005c6457ec088d532f482093965ae53ccd07e556ed59e2af945cd8c7a95c1c644f8a56a8a8a3cd77392ddd861e8a924dac99c69069093bd52a52fa6c56004a074508007878d6d42e4b4dd1e9c0696cb3e19f63033c3db4e60d473259b3ebe079aaf0a986ee6177f8217a78c68b813f7e149a4e56fd9562c07fed3d895942d7d101cb83f6"
)

func hexDecode(t *testing.T, hexStr string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("hex.DecodeString(%v) err = %v, want nil", hexStr, err)
	}
	return decoded
}

func marshalPublicKey(t *testing.T, protoPubKey *ecdsapb.EcdsaPublicKey) []byte {
	serializedProtoPubKey, err := proto.Marshal(protoPubKey)
	if err != nil {
		t.Fatalf("proto.Marshal(protoPubKey) err = %v, want nil", err)
	}
	return serializedProtoPubKey
}

type testParams struct{}

func (p *testParams) HasIDRequirement() bool { return true }

func (p *testParams) Equals(params key.Parameters) bool { return true }

type testKey struct{}

func (k *testKey) Parameters() key.Parameters { return &testParams{} }

func (k *testKey) Equals(other key.Key) bool { return true }

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
			publicKey: &PublicKey{},
		},
		{
			name:      "incorrect key type",
			publicKey: &testKey{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &publicKeySerializer{}
			if _, err := s.SerializeKey(tc.publicKey); err == nil {
				t.Errorf("s.SerializeKey(%v) err = nil, want non-nil", tc.publicKey)
			}
		})
	}
}

func TestSerializePublicKey(t *testing.T) {
	for _, tc := range testCases(t) {
		if !tc.hasLeadingZeros {
			// We expect coordinates to have a fixed size encoding:
			// 		 x' = 0x00 || x, y' = 0x00 || y
			// With: len(x') = len(y') = coordinateSizeForCurve(tc.publicKey.parameters.curveType) + 1.
			continue
		}
		name := fmt.Sprintf("curveType:%v_hashType:%v_encoding:%v_variant:%v_id:%d", tc.publicKey.parameters.curveType, tc.publicKey.parameters.hashType, tc.publicKey.parameters.signatureEncoding, tc.publicKey.parameters.variant, tc.publicKey.idRequirement)
		t.Run(name, func(t *testing.T) {
			s := &publicKeySerializer{}
			got, err := s.SerializeKey(tc.publicKey)
			if err != nil {
				t.Fatalf("s.SerializeKey(%v) err = nil, want non-nil", tc.publicKey)
			}
			if !got.Equals(tc.keySerialization) {
				t.Errorf("got = %v, want %v", got, tc.keySerialization)
			}
		})
	}
}

func TestParsePublicKeyFails(t *testing.T) {
	xP256, yP256 := hexDecode(t, pubKeyXP256Hex), hexDecode(t, pubKeyYP256Hex)
	protoPublicKey := &ecdsapb.EcdsaPublicKey{
		X: xP256,
		Y: yP256,
		Params: &ecdsapb.EcdsaParams{
			Curve:    commonpb.EllipticCurveType_NIST_P256,
			HashType: commonpb.HashType_SHA256,
			Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
		},
		Version: verifierKeyVersion,
	}
	serializedProtoPublicKey := marshalPublicKey(t, protoPublicKey)
	xP521, yP521 := hexDecode(t, pubKeyXP521Hex), hexDecode(t, pubKeyYP521Hex)

	for _, tc := range []struct {
		name             string
		keySerialization *protoserialization.KeySerialization
	}{
		{
			name:             "key data is nil",
			keySerialization: newKeySerialization(t, nil, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong type URL",
			keySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "invalid_type_url",
				Value:           serializedProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong key material type",
			keySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serializedProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong key version",
			keySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: verifierTypeURL,
				Value: marshalPublicKey(t, &ecdsapb.EcdsaPublicKey{
					X: xP256,
					Y: yP256,
					Params: &ecdsapb.EcdsaParams{
						Curve:    commonpb.EllipticCurveType_NIST_P256,
						HashType: commonpb.HashType_SHA256,
						Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
					},
					Version: verifierKeyVersion + 1,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "point not on curve",
			keySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: verifierTypeURL,
				Value: marshalPublicKey(t, &ecdsapb.EcdsaPublicKey{
					X: xP256,
					Y: []byte("00000000000000000000000000000001"),
					Params: &ecdsapb.EcdsaParams{
						Curve:    commonpb.EllipticCurveType_NIST_P256,
						HashType: commonpb.HashType_SHA256,
						Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
					},
					Version: verifierKeyVersion,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "point coordinate after leading 0s removal too long",
			keySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: verifierTypeURL,
				Value: marshalPublicKey(t, &ecdsapb.EcdsaPublicKey{
					X: append(xP256, 0x02),
					Y: yP256,
					Params: &ecdsapb.EcdsaParams{
						Curve:    commonpb.EllipticCurveType_NIST_P256,
						HashType: commonpb.HashType_SHA256,
						Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
					},
					Version: verifierKeyVersion,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "invalid point",
			keySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: verifierTypeURL,
				Value: marshalPublicKey(t, &ecdsapb.EcdsaPublicKey{
					X: []byte("0"),
					Y: []byte("0"),
					Params: &ecdsapb.EcdsaParams{
						Curve:    commonpb.EllipticCurveType_NIST_P256,
						HashType: commonpb.HashType_SHA256,
						Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
					},
					Version: verifierKeyVersion,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "point from another curve",
			keySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: verifierTypeURL,
				Value: marshalPublicKey(t, &ecdsapb.EcdsaPublicKey{
					X: xP521,
					Y: yP521,
					Params: &ecdsapb.EcdsaParams{
						Curve:    commonpb.EllipticCurveType_NIST_P256,
						HashType: commonpb.HashType_SHA256,
						Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
					},
					Version: verifierKeyVersion,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "unknown curve type",
			keySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: verifierTypeURL,
				Value: marshalPublicKey(t, &ecdsapb.EcdsaPublicKey{
					X: xP256,
					Y: yP256,
					Params: &ecdsapb.EcdsaParams{
						Curve:    commonpb.EllipticCurveType_UNKNOWN_CURVE,
						HashType: commonpb.HashType_SHA256,
						Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
					},
					Version: verifierKeyVersion,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "unknown hash type",
			keySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: verifierTypeURL,
				Value: marshalPublicKey(t, &ecdsapb.EcdsaPublicKey{
					X: xP256,
					Y: yP256,
					Params: &ecdsapb.EcdsaParams{
						Curve:    commonpb.EllipticCurveType_NIST_P256,
						HashType: commonpb.HashType_UNKNOWN_HASH,
						Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
					},
					Version: verifierKeyVersion,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "unknown encoding",
			keySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: verifierTypeURL,
				Value: marshalPublicKey(t, &ecdsapb.EcdsaPublicKey{
					X: xP256,
					Y: yP256,
					Params: &ecdsapb.EcdsaParams{
						Curve:    commonpb.EllipticCurveType_NIST_P256,
						HashType: commonpb.HashType_SHA256,
						Encoding: ecdsapb.EcdsaSignatureEncoding_UNKNOWN_ENCODING,
					},
					Version: verifierKeyVersion,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &publicKeyParser{}
			if _, err := p.ParseKey(tc.keySerialization); err == nil {
				t.Errorf("p.ParseKey(%v) err = nil, want non-nil", tc.keySerialization)
			} else {
				t.Logf("p.ParseKey(%v) err = %v", tc.keySerialization, err)
			}
		})
	}
}

func newPublicKey(t *testing.T, uncompressedPoint []byte, idRequirement uint32, params *Parameters) *PublicKey {
	t.Helper()
	outputPrefix, err := calculateOutputPrefix(params.variant, idRequirement)
	if err != nil {
		t.Fatalf("calculateOutputPrefix(%v, %v) err = %v, want nil", params.variant, idRequirement, err)
	}
	return &PublicKey{
		publicPoint:   uncompressedPoint,
		idRequirement: idRequirement,
		outputPrefix:  outputPrefix,
		parameters:    params,
	}
}

type publicKeyTestCase struct {
	keySerialization *protoserialization.KeySerialization
	publicKey        *PublicKey
	hasLeadingZeros  bool
}

func testCases(t *testing.T) []publicKeyTestCase {
	tc := []publicKeyTestCase{}
	for _, variantAndID := range []struct {
		protoPrefixType tinkpb.OutputPrefixType
		variant         Variant
		id              uint32
	}{
		{
			protoPrefixType: tinkpb.OutputPrefixType_TINK,
			variant:         VariantTink,
			id:              123,
		},
		{
			protoPrefixType: tinkpb.OutputPrefixType_LEGACY,
			variant:         VariantLegacy,
			id:              123,
		},
		{
			protoPrefixType: tinkpb.OutputPrefixType_RAW,
			variant:         VariantNoPrefix,
			id:              0,
		},
		{
			protoPrefixType: tinkpb.OutputPrefixType_CRUNCHY,
			variant:         VariantCrunchy,
			id:              123,
		},
	} {
		for _, encoding := range []struct {
			protoEncoding ecdsapb.EcdsaSignatureEncoding
			encoding      SignatureEncoding
		}{
			{
				protoEncoding: ecdsapb.EcdsaSignatureEncoding_DER,
				encoding:      DER,
			},
			{
				protoEncoding: ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
				encoding:      IEEEP1363,
			},
		} {
			for _, curveType := range []commonpb.EllipticCurveType{commonpb.EllipticCurveType_NIST_P256, commonpb.EllipticCurveType_NIST_P384, commonpb.EllipticCurveType_NIST_P521} {
				for _, hasLeadingZeros := range []bool{false, true} {
					switch curveType {
					case commonpb.EllipticCurveType_NIST_P256:
						{
							x, y := hexDecode(t, pubKeyXP256Hex), hexDecode(t, pubKeyYP256Hex)
							if hasLeadingZeros {
								x = append([]byte{0x00}, x...)
								y = append([]byte{0x00}, y...)
							}
							uncompressedPoint := hexDecode(t, uncompressedP256Hex)
							tc = append(tc, publicKeyTestCase{
								keySerialization: newKeySerialization(t, &tinkpb.KeyData{
									TypeUrl: verifierTypeURL,
									Value: marshalPublicKey(t, &ecdsapb.EcdsaPublicKey{
										X: x,
										Y: y,
										Params: &ecdsapb.EcdsaParams{
											Curve:    curveType,
											HashType: commonpb.HashType_SHA256,
											Encoding: encoding.protoEncoding,
										},
										Version: verifierKeyVersion,
									}),
									KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
								}, variantAndID.protoPrefixType, variantAndID.id),
								publicKey: newPublicKey(t, uncompressedPoint, variantAndID.id, &Parameters{
									curveType:         NistP256,
									hashType:          SHA256,
									signatureEncoding: encoding.encoding,
									variant:           variantAndID.variant,
								}),
								hasLeadingZeros: hasLeadingZeros,
							})
						}
					case commonpb.EllipticCurveType_NIST_P384:
						{
							x, y := hexDecode(t, pubKeyXP384Hex), hexDecode(t, pubKeyYP384Hex)
							if hasLeadingZeros {
								x = append([]byte{0x00}, x...)
								y = append([]byte{0x00}, y...)
							}
							uncompressedPoint := hexDecode(t, uncompressedP384Hex)
							tc = append(tc, publicKeyTestCase{
								keySerialization: newKeySerialization(t, &tinkpb.KeyData{
									TypeUrl: verifierTypeURL,
									Value: marshalPublicKey(t, &ecdsapb.EcdsaPublicKey{
										X: x,
										Y: y,
										Params: &ecdsapb.EcdsaParams{
											Curve:    curveType,
											HashType: commonpb.HashType_SHA384,
											Encoding: encoding.protoEncoding,
										},
										Version: verifierKeyVersion,
									}),
									KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
								}, variantAndID.protoPrefixType, variantAndID.id),
								publicKey: newPublicKey(t, uncompressedPoint, variantAndID.id, &Parameters{
									curveType:         NistP384,
									hashType:          SHA384,
									signatureEncoding: encoding.encoding,
									variant:           variantAndID.variant,
								}),
								hasLeadingZeros: hasLeadingZeros,
							})
							tc = append(tc, publicKeyTestCase{
								keySerialization: newKeySerialization(t, &tinkpb.KeyData{
									TypeUrl: verifierTypeURL,
									Value: marshalPublicKey(t, &ecdsapb.EcdsaPublicKey{
										X: x,
										Y: y,
										Params: &ecdsapb.EcdsaParams{
											Curve:    curveType,
											HashType: commonpb.HashType_SHA512,
											Encoding: encoding.protoEncoding,
										},
										Version: verifierKeyVersion,
									}),
									KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
								}, variantAndID.protoPrefixType, variantAndID.id),
								publicKey: newPublicKey(t, uncompressedPoint, variantAndID.id, &Parameters{
									curveType:         NistP384,
									hashType:          SHA512,
									signatureEncoding: encoding.encoding,
									variant:           variantAndID.variant,
								}),
								hasLeadingZeros: hasLeadingZeros,
							})
						}
					case commonpb.EllipticCurveType_NIST_P521:
						{
							x, y := hexDecode(t, pubKeyXP521Hex), hexDecode(t, pubKeyYP521Hex)
							if hasLeadingZeros {
								x = append([]byte{0x00}, x...)
								y = append([]byte{0x00}, y...)
							}
							uncompressedPoint := hexDecode(t, uncompressedP521Hex)
							tc = append(tc, publicKeyTestCase{
								keySerialization: newKeySerialization(t, &tinkpb.KeyData{
									TypeUrl: verifierTypeURL,
									Value: marshalPublicKey(t, &ecdsapb.EcdsaPublicKey{
										X: x,
										Y: y,
										Params: &ecdsapb.EcdsaParams{
											Curve:    curveType,
											HashType: commonpb.HashType_SHA512,
											Encoding: encoding.protoEncoding,
										},
										Version: verifierKeyVersion,
									}),
									KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
								}, variantAndID.protoPrefixType, variantAndID.id),
								publicKey: newPublicKey(t, uncompressedPoint, variantAndID.id, &Parameters{
									curveType:         NistP521,
									hashType:          SHA512,
									signatureEncoding: encoding.encoding,
									variant:           variantAndID.variant,
								}),
							})
						}
					}
				}
			}
		}
	}
	return tc
}

func TestParsePublicKey(t *testing.T) {
	for _, tc := range testCases(t) {
		name := fmt.Sprintf("curveType:%v_hashType:%v_encoding:%v_variant:%v_id:%d_hasLeadingZeros:%v", tc.publicKey.parameters.curveType, tc.publicKey.parameters.hashType, tc.publicKey.parameters.signatureEncoding, tc.publicKey.parameters.variant, tc.publicKey.idRequirement, tc.hasLeadingZeros)
		t.Run(name, func(t *testing.T) {
			p := &publicKeyParser{}
			gotPublicKey, err := p.ParseKey(tc.keySerialization)
			if err != nil {
				t.Fatalf("p.ParseKey(%v) err = %v, want non-nil", tc.keySerialization, err)
			}
			if !gotPublicKey.Equals(tc.publicKey) {
				t.Errorf("%v.Equals(%v) = false, want true", gotPublicKey, tc.publicKey)
			}
		})
	}
	// P521 point with a Y coordinate of 65 bytes.
	// Taken from
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/ecdsa_secp521r1_sha3_512_test.json#L3093.
	pubKeyXP521Hex65Bytes := "01f974fbc98b55c4d39797fe6ff8891eab2aa541e8767a1b9e9eaef1f94895cdf6373c90ccb3643d1b2ef3154b126de937e4343f2409b191c262e3ac1e2577606e58"
	pubKeyYP521Hex65Bytes := "6ed880d925e876beba3102432752ce237b8682c65ceb59902fd6dc7b6f8c728e5078e8676912ae822fda39cb62023fa4fd85bab6d32f3857914aae2d0b7e04e958"
	pubKeyP521Hex65BytesCompressed := "0401f974fbc98b55c4d39797fe6ff8891eab2aa541e8767a1b9e9eaef1f94895cdf6373c90ccb3643d1b2ef3154b126de937e4343f2409b191c262e3ac1e2577606e58006ed880d925e876beba3102432752ce237b8682c65ceb59902fd6dc7b6f8c728e5078e8676912ae822fda39cb62023fa4fd85bab6d32f3857914aae2d0b7e04e958"
	x, y := hexDecode(t, pubKeyXP521Hex65Bytes), hexDecode(t, pubKeyYP521Hex65Bytes)
	uncompressedPoint := hexDecode(t, pubKeyP521Hex65BytesCompressed)
	t.Run("curveType:NIST_P521_hashType:SHA512_encoding:DER_variant:TINK_id:123_YBytesLength:65", func(t *testing.T) {
		keySerialization := newKeySerialization(t, &tinkpb.KeyData{
			TypeUrl: verifierTypeURL,
			Value: marshalPublicKey(t, &ecdsapb.EcdsaPublicKey{
				X: x,
				Y: y,
				Params: &ecdsapb.EcdsaParams{
					Curve:    commonpb.EllipticCurveType_NIST_P521,
					HashType: commonpb.HashType_SHA512,
					Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
				},
				Version: verifierKeyVersion,
			}),
			KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
		}, tinkpb.OutputPrefixType_TINK, 123)
		publicKey :=
			newPublicKey(t, uncompressedPoint, 123, &Parameters{
				curveType:         NistP521,
				hashType:          SHA512,
				signatureEncoding: DER,
				variant:           VariantTink,
			})
		p := &publicKeyParser{}
		gotPublicKey, err := p.ParseKey(keySerialization)
		if err != nil {
			t.Fatalf("p.ParseKey(%v) err = %v, want non-nil", keySerialization, err)
		}
		if !gotPublicKey.Equals(publicKey) {
			t.Errorf("%v.Equals(%v) = false, want true", gotPublicKey, publicKey)
		}
	})
}
