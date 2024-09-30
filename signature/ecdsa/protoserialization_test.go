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
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
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
	// Taken from https://datatracker.ietf.org/doc/html/rfc6979.html#appendix-A.2.5
	pubKeyXP256Hex      = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
	pubKeyYP256Hex      = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"
	privKeyValueP256Hex = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
	uncompressedP256Hex = "04" + pubKeyXP256Hex + pubKeyYP256Hex

	// Taken from https://datatracker.ietf.org/doc/html/rfc6979.html#appendix-A.2.6
	pubKeyXP384Hex      = "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13"
	pubKeyYP384Hex      = "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720"
	privKeyValueP384Hex = "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5"
	uncompressedP384Hex = "04" + pubKeyXP384Hex + pubKeyYP384Hex

	// Taken from https://datatracker.ietf.org/doc/html/rfc6979.html#appendix-A.2.7
	pubKeyXP521Hex      = "01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4"
	pubKeyYP521Hex      = "00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5"
	privKeyValueP521Hex = "00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538"
	uncompressedP521Hex = "04" + pubKeyXP521Hex + pubKeyYP521Hex
)

func hexDecode(t *testing.T, hexStr string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("hex.DecodeString(%v) err = %v, want nil", hexStr, err)
	}
	return decoded
}

func marshalKey(t *testing.T, message proto.Message) []byte {
	serializedProtoPubKey, err := proto.Marshal(message)
	if err != nil {
		t.Fatalf("proto.Marshal(message) err = %v, want nil", err)
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
			if !got.Equals(tc.publicKeySerialization) {
				t.Errorf("got = %v, want %v", got, tc.publicKeySerialization)
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
	serializedProtoPublicKey := marshalKey(t, protoPublicKey)
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
				Value: marshalKey(t, &ecdsapb.EcdsaPublicKey{
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
				Value: marshalKey(t, &ecdsapb.EcdsaPublicKey{
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
				Value: marshalKey(t, &ecdsapb.EcdsaPublicKey{
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
				Value: marshalKey(t, &ecdsapb.EcdsaPublicKey{
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
				Value: marshalKey(t, &ecdsapb.EcdsaPublicKey{
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
				Value: marshalKey(t, &ecdsapb.EcdsaPublicKey{
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
				Value: marshalKey(t, &ecdsapb.EcdsaPublicKey{
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
				Value: marshalKey(t, &ecdsapb.EcdsaPublicKey{
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

func newPrivateKey(t *testing.T, privateKeyValue secretdata.Bytes, publicKey *PublicKey) *PrivateKey {
	t.Helper()
	privateKey, err := NewPrivateKeyFromPublicKey(publicKey, privateKeyValue)
	if err != nil {
		t.Fatalf("NewPrivateKeyFromPublicKey(%v, %v) err = %v, want nil", publicKey, privateKeyValue, err)
	}
	return privateKey
}

type testCase struct {
	publicKey               *PublicKey
	publicKeySerialization  *protoserialization.KeySerialization
	privateKey              *PrivateKey
	privateKeySerialization *protoserialization.KeySerialization
	hasLeadingZeros         bool
}

func testCases(t *testing.T) []testCase {
	tc := []testCase{}
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
					token := insecuresecretdataaccess.Token{}
					switch curveType {
					case commonpb.EllipticCurveType_NIST_P256:
						{
							x, y, privateKeyValue := hexDecode(t, pubKeyXP256Hex), hexDecode(t, pubKeyYP256Hex), hexDecode(t, privKeyValueP256Hex)
							uncompressedPoint := hexDecode(t, uncompressedP256Hex)
							publicKey := newPublicKey(t, uncompressedPoint, variantAndID.id, &Parameters{
								curveType:         NistP256,
								hashType:          SHA256,
								signatureEncoding: encoding.encoding,
								variant:           variantAndID.variant,
							})
							privateKey := newPrivateKey(t, secretdata.NewBytesFromData(privateKeyValue, token), publicKey)
							var privateKeyValueForProto []byte
							if hasLeadingZeros {
								x = append([]byte{0x00}, x...)
								y = append([]byte{0x00}, y...)
								privateKeyValueForProto = append([]byte{0x00}, privateKeyValue...)
							} else {
								privateKeyValueForProto = privateKeyValue
							}
							protoPublicKey := &ecdsapb.EcdsaPublicKey{
								X: x,
								Y: y,
								Params: &ecdsapb.EcdsaParams{
									Curve:    curveType,
									HashType: commonpb.HashType_SHA256,
									Encoding: encoding.protoEncoding,
								},
								Version: verifierKeyVersion,
							}
							protoPrivateKey := &ecdsapb.EcdsaPrivateKey{
								Version:   signerKeyVersion,
								KeyValue:  privateKeyValueForProto,
								PublicKey: protoPublicKey,
							}
							tc = append(tc, testCase{
								publicKeySerialization: newKeySerialization(t, &tinkpb.KeyData{
									TypeUrl:         verifierTypeURL,
									Value:           marshalKey(t, protoPublicKey),
									KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
								}, variantAndID.protoPrefixType, variantAndID.id),
								publicKey: publicKey,
								privateKeySerialization: newKeySerialization(t, &tinkpb.KeyData{
									TypeUrl:         signerTypeURL,
									Value:           marshalKey(t, protoPrivateKey),
									KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
								}, variantAndID.protoPrefixType, variantAndID.id),
								privateKey:      privateKey,
								hasLeadingZeros: hasLeadingZeros,
							})
						}
					case commonpb.EllipticCurveType_NIST_P384:
						{
							x, y, privateKeyValue := hexDecode(t, pubKeyXP384Hex), hexDecode(t, pubKeyYP384Hex), hexDecode(t, privKeyValueP384Hex)
							uncompressedPoint := hexDecode(t, uncompressedP384Hex)
							var privateKeyValueForProto []byte
							if hasLeadingZeros {
								x = append([]byte{0x00}, x...)
								y = append([]byte{0x00}, y...)
								privateKeyValueForProto = append([]byte{0x00}, privateKeyValue...)
							} else {
								privateKeyValueForProto = privateKeyValue
							}

							// hashType: SHA384.
							publicKeySHA384 := newPublicKey(t, uncompressedPoint, variantAndID.id, &Parameters{
								curveType:         NistP384,
								hashType:          SHA384,
								signatureEncoding: encoding.encoding,
								variant:           variantAndID.variant,
							})
							privateKeySHA384 := newPrivateKey(t, secretdata.NewBytesFromData(privateKeyValue, token), publicKeySHA384)

							protoPublicKeySHA384 := &ecdsapb.EcdsaPublicKey{
								X: x,
								Y: y,
								Params: &ecdsapb.EcdsaParams{
									Curve:    curveType,
									HashType: commonpb.HashType_SHA384,
									Encoding: encoding.protoEncoding,
								},
								Version: verifierKeyVersion,
							}
							protoPrivateKeySHA384 := &ecdsapb.EcdsaPrivateKey{
								Version:   signerKeyVersion,
								KeyValue:  privateKeyValueForProto,
								PublicKey: protoPublicKeySHA384,
							}

							tc = append(tc, testCase{
								publicKeySerialization: newKeySerialization(t, &tinkpb.KeyData{
									TypeUrl:         verifierTypeURL,
									Value:           marshalKey(t, protoPublicKeySHA384),
									KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
								}, variantAndID.protoPrefixType, variantAndID.id),
								publicKey: publicKeySHA384,
								privateKeySerialization: newKeySerialization(t, &tinkpb.KeyData{
									TypeUrl:         signerTypeURL,
									Value:           marshalKey(t, protoPrivateKeySHA384),
									KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
								}, variantAndID.protoPrefixType, variantAndID.id),
								privateKey:      privateKeySHA384,
								hasLeadingZeros: hasLeadingZeros,
							})

							// hashType: SHA512.
							protoPublicKeySHA512 := &ecdsapb.EcdsaPublicKey{
								X: x,
								Y: y,
								Params: &ecdsapb.EcdsaParams{
									Curve:    curveType,
									HashType: commonpb.HashType_SHA512,
									Encoding: encoding.protoEncoding,
								},
								Version: verifierKeyVersion,
							}
							protoPrivateKeySHA512 := &ecdsapb.EcdsaPrivateKey{
								Version:   signerKeyVersion,
								KeyValue:  privateKeyValueForProto,
								PublicKey: protoPublicKeySHA512,
							}
							publicKeySHA512 := newPublicKey(t, uncompressedPoint, variantAndID.id, &Parameters{
								curveType:         NistP384,
								hashType:          SHA512,
								signatureEncoding: encoding.encoding,
								variant:           variantAndID.variant,
							})
							privateKeySHA512 := newPrivateKey(t, secretdata.NewBytesFromData(privateKeyValue, token), publicKeySHA512)

							tc = append(tc, testCase{
								publicKeySerialization: newKeySerialization(t, &tinkpb.KeyData{
									TypeUrl:         verifierTypeURL,
									Value:           marshalKey(t, protoPublicKeySHA512),
									KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
								}, variantAndID.protoPrefixType, variantAndID.id),
								publicKey: publicKeySHA512,
								privateKeySerialization: newKeySerialization(t, &tinkpb.KeyData{
									TypeUrl:         signerTypeURL,
									Value:           marshalKey(t, protoPrivateKeySHA512),
									KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
								}, variantAndID.protoPrefixType, variantAndID.id),
								privateKey:      privateKeySHA512,
								hasLeadingZeros: hasLeadingZeros,
							})
						}
					case commonpb.EllipticCurveType_NIST_P521:
						{
							x, y, privateKeyValue := hexDecode(t, pubKeyXP521Hex), hexDecode(t, pubKeyYP521Hex), hexDecode(t, privKeyValueP521Hex)
							var privateKeyValueForProto []byte
							if hasLeadingZeros {
								x = append([]byte{0x00}, x...)
								y = append([]byte{0x00}, y...)
								privateKeyValueForProto = append([]byte{0x00}, privateKeyValue...)
							} else {
								privateKeyValueForProto = privateKeyValue
							}
							uncompressedPoint := hexDecode(t, uncompressedP521Hex)
							publicKey := newPublicKey(t, uncompressedPoint, variantAndID.id, &Parameters{
								curveType:         NistP521,
								hashType:          SHA512,
								signatureEncoding: encoding.encoding,
								variant:           variantAndID.variant,
							})
							protoPublicKey := &ecdsapb.EcdsaPublicKey{
								X: x,
								Y: y,
								Params: &ecdsapb.EcdsaParams{
									Curve:    curveType,
									HashType: commonpb.HashType_SHA512,
									Encoding: encoding.protoEncoding,
								},
								Version: verifierKeyVersion,
							}
							protoPrivateKey := &ecdsapb.EcdsaPrivateKey{
								Version:   signerKeyVersion,
								KeyValue:  privateKeyValueForProto,
								PublicKey: protoPublicKey,
							}

							tc = append(tc, testCase{
								publicKeySerialization: newKeySerialization(t, &tinkpb.KeyData{
									TypeUrl:         verifierTypeURL,
									Value:           marshalKey(t, protoPublicKey),
									KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
								}, variantAndID.protoPrefixType, variantAndID.id),
								publicKey: publicKey,
								privateKeySerialization: newKeySerialization(t, &tinkpb.KeyData{
									TypeUrl:         signerTypeURL,
									Value:           marshalKey(t, protoPrivateKey),
									KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
								}, variantAndID.protoPrefixType, variantAndID.id),
								privateKey:      newPrivateKey(t, secretdata.NewBytesFromData(privateKeyValue, token), publicKey),
								hasLeadingZeros: hasLeadingZeros,
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
			gotPublicKey, err := p.ParseKey(tc.publicKeySerialization)
			if err != nil {
				t.Fatalf("p.ParseKey(%v) err = %v, want non-nil", tc.publicKeySerialization, err)
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
		publicKeySerialization := newKeySerialization(t, &tinkpb.KeyData{
			TypeUrl: verifierTypeURL,
			Value: marshalKey(t, &ecdsapb.EcdsaPublicKey{
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
		gotPublicKey, err := p.ParseKey(publicKeySerialization)
		if err != nil {
			t.Fatalf("p.ParseKey(%v) err = %v, want non-nil", publicKeySerialization, err)
		}
		if !gotPublicKey.Equals(publicKey) {
			t.Errorf("%v.Equals(%v) = false, want true", gotPublicKey, publicKey)
		}
	})
}

func TestSerializePrivateKey(t *testing.T) {
	for _, tc := range testCases(t) {
		if !tc.hasLeadingZeros {
			// We expect coordinates to have a fixed size encoding:
			// 		 Public key point: 	x' = 0x00 || x, y' = 0x00 || y
			//		 Private key: 			d' = 0x00 || d
			// With: len(x') = len(y') = len(d') = coordinateSizeForCurve(tc.publicKey.parameters.curveType) + 1.
			continue
		}
		name := fmt.Sprintf("curveType:%v_hashType:%v_encoding:%v_variant:%v_id:%d", tc.publicKey.parameters.curveType, tc.publicKey.parameters.hashType, tc.publicKey.parameters.signatureEncoding, tc.publicKey.parameters.variant, tc.publicKey.idRequirement)
		t.Run(name, func(t *testing.T) {
			s := &privateKeySerializer{}
			got, err := s.SerializeKey(tc.privateKey)
			if err != nil {
				t.Fatalf("s.SerializeKey(%v) err = nil, want non-nil", tc.privateKey)
			}
			if !got.Equals(tc.privateKeySerialization) {
				t.Errorf("got = %v, want %v", got, tc.privateKeySerialization)
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
			name:       "nil private key",
			privateKey: nil,
		},
		{
			name:       "invalid private key",
			privateKey: &PrivateKey{},
		},
		{
			name:       "incorrect key type",
			privateKey: &testKey{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &privateKeySerializer{}
			if _, err := s.SerializeKey(tc.privateKey); err == nil {
				t.Errorf("s.SerializeKey(%v) err = nil, want non-nil", tc.privateKey)
			}
		})
	}
}
