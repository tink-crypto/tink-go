// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prfbasedkeyderivation_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyderivation/prfbasedkeyderivation"
	"github.com/tink-crypto/tink-go/v2/prf/aescmacprf"
	"github.com/tink-crypto/tink-go/v2/prf/hkdfprf"
	"github.com/tink-crypto/tink-go/v2/prf/hmacprf"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testutil/testonlyinsecuresecretdataaccess"
	aescmacprfpb "github.com/tink-crypto/tink-go/v2/proto/aes_cmac_prf_go_proto"
	aesgcmpb "github.com/tink-crypto/tink-go/v2/proto/aes_gcm_go_proto"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	hkdfprfpb "github.com/tink-crypto/tink-go/v2/proto/hkdf_prf_go_proto"
	hmacpb "github.com/tink-crypto/tink-go/v2/proto/hmac_prf_go_proto"
	hmacprfpb "github.com/tink-crypto/tink-go/v2/proto/hmac_prf_go_proto"
	prfderpb "github.com/tink-crypto/tink-go/v2/proto/prf_based_deriver_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func mustMarshal(t *testing.T, message proto.Message) []byte {
	t.Helper()
	serializedMessage, err := proto.Marshal(message)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", message, err)
	}
	return serializedMessage
}

func mustCreateKeySerialization(t *testing.T, keyData *tinkpb.KeyData, outputPrefixType tinkpb.OutputPrefixType, idRequirement uint32) *protoserialization.KeySerialization {
	t.Helper()
	ks, err := protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
	if err != nil {
		t.Fatalf("protoserialization.NewKeySerialization(%v, %v, %v) err = %v, want nil", keyData, outputPrefixType, idRequirement, err)
	}
	return ks
}

type keyParsingTestCase struct {
	name             string
	keySerialization *protoserialization.KeySerialization
	key              *prfbasedkeyderivation.Key
}

func keyParsingTestCases(t *testing.T) []keyParsingTestCase {
	// PRF keys.
	aesCMACPRFKey, err := aescmacprf.NewKey(secretdata.NewBytesFromData([]byte("01234567890123456789012345678901"), testonlyinsecuresecretdataaccess.Token()))
	if err != nil {
		t.Fatalf("aescmacprf.NewKey() failed: %v", err)
	}
	aesCMACPRFParams := aesCMACPRFKey.Parameters().(*aescmacprf.Parameters)

	hmacPRFParams, err := hmacprf.NewParameters(32, hmacprf.SHA256)
	if err != nil {
		t.Fatalf("hmacprf.NewParameters(32, hmacprf.SHA256) failed: %v", err)
	}
	hmacPRFKey, err := hmacprf.NewKey(secretdata.NewBytesFromData([]byte("01234567890123456789012345678901"), testonlyinsecuresecretdataaccess.Token()), hmacPRFParams)
	if err != nil {
		t.Fatalf("hmacprf.NewKey() failed: %v", err)
	}

	hkdfPRFParams, err := hkdfprf.NewParameters(32, hkdfprf.SHA256, []byte("salt"))
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters(32, hkdfprf.SHA25, []byte(\"salt\")) failed: %v", err)
	}
	hkdfPRFKey, err := hkdfprf.NewKey(secretdata.NewBytesFromData([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"), testonlyinsecuresecretdataaccess.Token()), hkdfPRFParams)
	if err != nil {
		t.Fatalf("hkdfprf.NewKey() failed: %v", err)
	}

	// Derived key parameters.
	derivedKeyParametersNoPrefix, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		IVSizeInBytes:  12,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() failed: %v", err)
	}
	derivedKeyParametersTinkPrefix, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		IVSizeInBytes:  12,
		Variant:        aesgcm.VariantTink,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() failed: %v", err)
	}
	return []keyParsingTestCase{
		{
			name: "AES-CMAC-PRF_with_tink_prefix",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
				Value: mustMarshal(t, &prfderpb.PrfBasedDeriverKey{
					Version: 0,
					PrfKey: &tinkpb.KeyData{
						TypeUrl: "type.googleapis.com/google.crypto.tink.AesCmacPrfKey",
						Value: mustMarshal(t, &aescmacprfpb.AesCmacPrfKey{
							Version:  0,
							KeyValue: []byte("01234567890123456789012345678901"),
						}),
						KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					},
					Params: &prfderpb.PrfBasedDeriverParams{
						DerivedKeyTemplate: &tinkpb.KeyTemplate{
							TypeUrl:          "type.googleapis.com/google.crypto.tink.AesGcmKey",
							OutputPrefixType: tinkpb.OutputPrefixType_TINK,
							Value: mustMarshal(t, &aesgcmpb.AesGcmKeyFormat{
								KeySize: 32,
							}),
						},
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
			key: mustCreateKey(t, aesCMACPRFParams, aesCMACPRFKey, derivedKeyParametersTinkPrefix, 12345),
		},
		{
			name: "AES-CMAC-PRF_with_RAW_prefix",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
				Value: mustMarshal(t, &prfderpb.PrfBasedDeriverKey{
					Version: 0,
					PrfKey: &tinkpb.KeyData{
						TypeUrl: "type.googleapis.com/google.crypto.tink.AesCmacPrfKey",
						Value: mustMarshal(t, &aescmacprfpb.AesCmacPrfKey{
							Version:  0,
							KeyValue: []byte("01234567890123456789012345678901"),
						}),
						KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					},
					Params: &prfderpb.PrfBasedDeriverParams{
						DerivedKeyTemplate: &tinkpb.KeyTemplate{
							TypeUrl:          "type.googleapis.com/google.crypto.tink.AesGcmKey",
							OutputPrefixType: tinkpb.OutputPrefixType_RAW,
							Value: mustMarshal(t, &aesgcmpb.AesGcmKeyFormat{
								KeySize: 32,
							}),
						},
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
			key: mustCreateKey(t, aesCMACPRFParams, aesCMACPRFKey, derivedKeyParametersNoPrefix, 0),
		},
		{
			name: "HMAC-PRF_with_tink_prefix",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
				Value: mustMarshal(t, &prfderpb.PrfBasedDeriverKey{
					Version: 0,
					PrfKey: &tinkpb.KeyData{
						TypeUrl: "type.googleapis.com/google.crypto.tink.HmacPrfKey",
						Value: mustMarshal(t, &hmacprfpb.HmacPrfKey{
							Version: 0,
							Params: &hmacprfpb.HmacPrfParams{
								Hash: commonpb.HashType_SHA256,
							},
							KeyValue: []byte("01234567890123456789012345678901"),
						}),
						KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					},
					Params: &prfderpb.PrfBasedDeriverParams{
						DerivedKeyTemplate: &tinkpb.KeyTemplate{
							TypeUrl:          "type.googleapis.com/google.crypto.tink.AesGcmKey",
							OutputPrefixType: tinkpb.OutputPrefixType_TINK,
							Value: mustMarshal(t, &aesgcmpb.AesGcmKeyFormat{
								KeySize: 32,
							}),
						},
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
			key: mustCreateKey(t, hmacPRFParams, hmacPRFKey, derivedKeyParametersTinkPrefix, 12345),
		},
		{
			name: "HMAC-PRF_with_RAW_prefix",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
				Value: mustMarshal(t, &prfderpb.PrfBasedDeriverKey{
					Version: 0,
					PrfKey: &tinkpb.KeyData{
						TypeUrl: "type.googleapis.com/google.crypto.tink.HmacPrfKey",
						Value: mustMarshal(t, &hmacprfpb.HmacPrfKey{
							Version: 0,
							Params: &hmacprfpb.HmacPrfParams{
								Hash: commonpb.HashType_SHA256,
							},
							KeyValue: []byte("01234567890123456789012345678901"),
						}),
						KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					},
					Params: &prfderpb.PrfBasedDeriverParams{
						DerivedKeyTemplate: &tinkpb.KeyTemplate{
							TypeUrl:          "type.googleapis.com/google.crypto.tink.AesGcmKey",
							OutputPrefixType: tinkpb.OutputPrefixType_RAW,
							Value: mustMarshal(t, &aesgcmpb.AesGcmKeyFormat{
								KeySize: 32,
							}),
						},
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
			key: mustCreateKey(t, hmacPRFParams, hmacPRFKey, derivedKeyParametersNoPrefix, 0),
		},
		{
			name: "HKDF-PRF_with_tink_prefix",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
				Value: mustMarshal(t, &prfderpb.PrfBasedDeriverKey{
					Version: 0,
					PrfKey: &tinkpb.KeyData{
						TypeUrl: "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
						Value: mustMarshal(t, &hkdfprfpb.HkdfPrfKey{
							Version: 0,
							Params: &hkdfprfpb.HkdfPrfParams{
								Hash: commonpb.HashType_SHA256,
								Salt: []byte("salt"),
							},
							KeyValue: []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"),
						}),
						KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					},
					Params: &prfderpb.PrfBasedDeriverParams{
						DerivedKeyTemplate: &tinkpb.KeyTemplate{
							TypeUrl:          "type.googleapis.com/google.crypto.tink.AesGcmKey",
							OutputPrefixType: tinkpb.OutputPrefixType_TINK,
							Value: mustMarshal(t, &aesgcmpb.AesGcmKeyFormat{
								KeySize: 32,
							}),
						},
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
			key: mustCreateKey(t, hkdfPRFParams, hkdfPRFKey, derivedKeyParametersTinkPrefix, 12345),
		},
		{
			name: "HKDF-PRF_with_RAW_prefix",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
				Value: mustMarshal(t, &prfderpb.PrfBasedDeriverKey{
					Version: 0,
					PrfKey: &tinkpb.KeyData{
						TypeUrl: "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
						Value: mustMarshal(t, &hkdfprfpb.HkdfPrfKey{
							Version: 0,
							Params: &hkdfprfpb.HkdfPrfParams{
								Hash: commonpb.HashType_SHA256,
								Salt: []byte("salt"),
							},
							KeyValue: []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"),
						}),
						KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					},
					Params: &prfderpb.PrfBasedDeriverParams{
						DerivedKeyTemplate: &tinkpb.KeyTemplate{
							TypeUrl:          "type.googleapis.com/google.crypto.tink.AesGcmKey",
							OutputPrefixType: tinkpb.OutputPrefixType_RAW,
							Value: mustMarshal(t, &aesgcmpb.AesGcmKeyFormat{
								KeySize: 32,
							}),
						},
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
			key: mustCreateKey(t, hkdfPRFParams, hkdfPRFKey, derivedKeyParametersNoPrefix, 0),
		},
	}
}

func TestParseKey_Success(t *testing.T) {
	for _, tc := range keyParsingTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.ParseKey(tc.keySerialization)
			if err != nil {
				t.Errorf("protoserialization.ParseKey(%v) err = %p, want nil", err, tc.keySerialization)
			}
			if diff := cmp.Diff(tc.key, got); diff != "" {
				t.Errorf("protoserialization.ParseKey(%v) returned diff (-want +got):\n%s", tc.keySerialization, diff)
			}
		})
	}
}

func TestParseKey_Failure(t *testing.T) {
	for _, tc := range []struct {
		name             string
		keySerialization *protoserialization.KeySerialization
	}{
		{
			name: "invalid PRF key URL",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
				Value: mustMarshal(t, &prfderpb.PrfBasedDeriverKey{
					Version: 0,
					PrfKey: &tinkpb.KeyData{
						TypeUrl: "type.googleapis.com/google.crypto.tink.DoesNotExist",
						Value: mustMarshal(t, &aescmacprfpb.AesCmacPrfKey{
							Version:  0,
							KeyValue: []byte("01234567890123456789012345678901"),
						}),
						KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					},
					Params: &prfderpb.PrfBasedDeriverParams{
						DerivedKeyTemplate: &tinkpb.KeyTemplate{
							TypeUrl:          "type.googleapis.com/google.crypto.tink.AesGcmKey",
							OutputPrefixType: tinkpb.OutputPrefixType_TINK,
							Value: mustMarshal(t, &aesgcmpb.AesGcmKeyFormat{
								KeySize: 16,
							}),
						},
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "nil PRF key",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
				Value: mustMarshal(t, &prfderpb.PrfBasedDeriverKey{
					Version: 0,
					PrfKey:  nil,
					Params: &prfderpb.PrfBasedDeriverParams{
						DerivedKeyTemplate: &tinkpb.KeyTemplate{
							TypeUrl:          "type.googleapis.com/google.crypto.tink.AesGcmKey",
							OutputPrefixType: tinkpb.OutputPrefixType_TINK,
							Value: mustMarshal(t, &aesgcmpb.AesGcmKeyFormat{
								KeySize: 16,
							}),
						},
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "invalid PRF key",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
				Value: mustMarshal(t, &prfderpb.PrfBasedDeriverKey{
					Version: 0,
					PrfKey: &tinkpb.KeyData{
						TypeUrl:         "type.googleapis.com/google.crypto.tink.AesCmacPrfKey",
						Value:           []byte("123"),
						KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					},
					Params: &prfderpb.PrfBasedDeriverParams{
						DerivedKeyTemplate: &tinkpb.KeyTemplate{
							TypeUrl:          "type.googleapis.com/google.crypto.tink.AesGcmKey",
							OutputPrefixType: tinkpb.OutputPrefixType_TINK,
							Value: mustMarshal(t, &aesgcmpb.AesGcmKeyFormat{
								KeySize: 16,
							}),
						},
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "invalid key material type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
				Value: mustMarshal(t, &prfderpb.PrfBasedDeriverKey{
					Version: 0,
					PrfKey: &tinkpb.KeyData{
						TypeUrl: "type.googleapis.com/google.crypto.tink.AesCmacPrfKey",
						Value: mustMarshal(t, &aescmacprfpb.AesCmacPrfKey{
							Version:  0,
							KeyValue: []byte("01234567890123456789012345678901"),
						}),
						KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					},
					Params: &prfderpb.PrfBasedDeriverParams{
						DerivedKeyTemplate: &tinkpb.KeyTemplate{
							TypeUrl:          "type.googleapis.com/google.crypto.tink.AesGcmKey",
							OutputPrefixType: tinkpb.OutputPrefixType_TINK,
							Value: mustMarshal(t, &aesgcmpb.AesGcmKeyFormat{
								KeySize: 16,
							}),
						},
					},
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "inconsistent output prefix type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
				Value: mustMarshal(t, &prfderpb.PrfBasedDeriverKey{
					Version: 0,
					PrfKey: &tinkpb.KeyData{
						TypeUrl: "type.googleapis.com/google.crypto.tink.AesCmacPrfKey",
						Value: mustMarshal(t, &aescmacprfpb.AesCmacPrfKey{
							Version:  0,
							KeyValue: []byte("01234567890123456789012345678901"),
						}),
						KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					},
					Params: &prfderpb.PrfBasedDeriverParams{
						DerivedKeyTemplate: &tinkpb.KeyTemplate{
							TypeUrl:          "type.googleapis.com/google.crypto.tink.AesGcmKey",
							OutputPrefixType: tinkpb.OutputPrefixType_TINK,
							Value: mustMarshal(t, &aesgcmpb.AesGcmKeyFormat{
								KeySize: 16,
							}),
						},
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_LEGACY, 12345),
		},
		{
			name: "invalid template URL",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
				Value: mustMarshal(t, &prfderpb.PrfBasedDeriverKey{
					Version: 0,
					PrfKey: &tinkpb.KeyData{
						TypeUrl: "type.googleapis.com/google.crypto.tink.AesCmacPrfKey",
						Value: mustMarshal(t, &aescmacprfpb.AesCmacPrfKey{
							Version:  0,
							KeyValue: []byte("01234567890123456789012345678901"),
						}),
						KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					},
					Params: &prfderpb.PrfBasedDeriverParams{
						DerivedKeyTemplate: &tinkpb.KeyTemplate{
							TypeUrl:          "type.googleapis.com/google.crypto.tink.DoesNotExist",
							OutputPrefixType: tinkpb.OutputPrefixType_TINK,
							Value: mustMarshal(t, &aesgcmpb.AesGcmKeyFormat{
								KeySize: 16,
							}),
						},
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 0),
		},
		{
			name: "invalid template",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
				Value: mustMarshal(t, &prfderpb.PrfBasedDeriverKey{
					Version: 0,
					PrfKey: &tinkpb.KeyData{
						TypeUrl: "type.googleapis.com/google.crypto.tink.AesCmacPrfKey",
						Value: mustMarshal(t, &aescmacprfpb.AesCmacPrfKey{
							Version:  0,
							KeyValue: []byte("01234567890123456789012345678901"),
						}),
						KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					},
					Params: &prfderpb.PrfBasedDeriverParams{
						DerivedKeyTemplate: &tinkpb.KeyTemplate{
							TypeUrl:          "type.googleapis.com/google.crypto.tink.AesGcmKey",
							OutputPrefixType: tinkpb.OutputPrefixType_TINK,
							Value:            []byte("invalid value"),
						},
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 0),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.ParseKey(tc.keySerialization); err == nil {
				t.Errorf("protoserialization.ParseKey(%v) err = nil, want error", tc.keySerialization)
			} else {
				t.Logf("protoserialization.ParseKey(%v) err = %v", tc.keySerialization, err)
			}
		})
	}
}

func TestSerializeKey_Success(t *testing.T) {
	for _, tc := range keyParsingTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.SerializeKey(tc.key)
			if err != nil {
				t.Errorf("protoserialization.SerializeKey(%v) err = %p, want nil", tc.key, err)
			}
			if diff := cmp.Diff(tc.keySerialization, got); diff != "" {
				t.Errorf("protoserialization.SerializeKey(%v) returned diff (-want +got):\n%s", tc.key, diff)
			}
		})
	}
}

type stubParams struct{}

var _ key.Parameters = (*stubParams)(nil)

func (p *stubParams) Equal(_ key.Parameters) bool { return true }
func (p *stubParams) HasIDRequirement() bool      { return true }

func TestSerializeKey_Failure(t *testing.T) {
	aesCMACPRFKey, err := aescmacprf.NewKey(secretdata.NewBytesFromData([]byte("01234567890123456789012345678901"), testonlyinsecuresecretdataaccess.Token()))
	if err != nil {
		t.Fatalf("aescmacprf.NewKey() failed: %v", err)
	}
	aesCMACPRFParams := aesCMACPRFKey.Parameters().(*aescmacprf.Parameters)
	for _, tc := range []struct {
		name string
		key  key.Key
	}{
		{
			name: "derived_key_parameters_not_serializable",
			key:  mustCreateKey(t, aesCMACPRFParams, aesCMACPRFKey, &stubParams{}, 12345),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.SerializeKey(tc.key); err == nil {
				t.Errorf("protoserialization.SerializeKey(%v) err = nil, want error", tc.key)
			}
		})
	}
}

func mustCreateParameters(t *testing.T, prfParams key.Parameters, derivedKeyParams key.Parameters) *prfbasedkeyderivation.Parameters {
	t.Helper()
	params, err := prfbasedkeyderivation.NewParameters(prfParams, derivedKeyParams)
	if err != nil {
		t.Fatalf("prfbasedkeyderivation.NewParameters(%v, %v) failed: %v", prfParams, derivedKeyParams, err)
	}
	return params
}

type paramsParsingTestCase struct {
	name     string
	template *tinkpb.KeyTemplate
	params   key.Parameters
}

func paramsParsingTestCases(t *testing.T) []paramsParsingTestCase {
	aesCMACPRFParams, err := aescmacprf.NewParameters(32)
	if err != nil {
		t.Fatalf("aescmacprf.NewParameters(32) failed: %v", err)
	}

	hmacPRFParams, err := hmacprf.NewParameters(32, hmacprf.SHA256)
	if err != nil {
		t.Fatalf("hmacprf.NewParameters(32, hmacprf.SHA256) failed: %v", err)
	}

	hkdfPRFParams, err := hkdfprf.NewParameters(32, hkdfprf.SHA256, []byte("salt"))
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters(32, hkdfprf.SHA25, []byte(\"salt\")) failed: %v", err)
	}

	// Derived key parameters.
	derivedKeyParametersNoPrefix, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		IVSizeInBytes:  12,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() failed: %v", err)
	}
	derivedKeyParametersTinkPrefix, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		IVSizeInBytes:  12,
		Variant:        aesgcm.VariantTink,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() failed: %v", err)
	}
	return []paramsParsingTestCase{
		{
			name: "AES-CMAC-PRF_with_tink_prefix",
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				Value: mustMarshal(t, &prfderpb.PrfBasedDeriverKeyFormat{
					PrfKeyTemplate: &tinkpb.KeyTemplate{
						TypeUrl:          "type.googleapis.com/google.crypto.tink.AesCmacPrfKey",
						OutputPrefixType: tinkpb.OutputPrefixType_RAW,
						Value: mustMarshal(t, &aescmacprfpb.AesCmacPrfKeyFormat{
							KeySize: 32,
						}),
					},
					Params: &prfderpb.PrfBasedDeriverParams{
						DerivedKeyTemplate: &tinkpb.KeyTemplate{
							TypeUrl:          "type.googleapis.com/google.crypto.tink.AesGcmKey",
							OutputPrefixType: tinkpb.OutputPrefixType_TINK,
							Value: mustMarshal(t, &aesgcmpb.AesGcmKeyFormat{
								KeySize: 32,
							}),
						},
					},
				}),
			},
			params: mustCreateParameters(t, &aesCMACPRFParams, derivedKeyParametersTinkPrefix),
		},
		{
			name: "AES-CMAC-PRF_no_prefix",
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
				Value: mustMarshal(t, &prfderpb.PrfBasedDeriverKeyFormat{
					PrfKeyTemplate: &tinkpb.KeyTemplate{
						TypeUrl:          "type.googleapis.com/google.crypto.tink.AesCmacPrfKey",
						OutputPrefixType: tinkpb.OutputPrefixType_RAW,
						Value: mustMarshal(t, &aescmacprfpb.AesCmacPrfKeyFormat{
							KeySize: 32,
						}),
					},
					Params: &prfderpb.PrfBasedDeriverParams{
						DerivedKeyTemplate: &tinkpb.KeyTemplate{
							TypeUrl:          "type.googleapis.com/google.crypto.tink.AesGcmKey",
							OutputPrefixType: tinkpb.OutputPrefixType_RAW,
							Value: mustMarshal(t, &aesgcmpb.AesGcmKeyFormat{
								KeySize: 32,
							}),
						},
					},
				}),
			},
			params: mustCreateParameters(t, &aesCMACPRFParams, derivedKeyParametersNoPrefix),
		},
		{
			name: "HKDF_with_tink_prefix",
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				Value: mustMarshal(t, &prfderpb.PrfBasedDeriverKeyFormat{
					PrfKeyTemplate: &tinkpb.KeyTemplate{
						TypeUrl:          "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
						OutputPrefixType: tinkpb.OutputPrefixType_RAW,
						Value: mustMarshal(t, &hkdfprfpb.HkdfPrfKeyFormat{
							Params: &hkdfprfpb.HkdfPrfParams{
								Hash: commonpb.HashType_SHA256,
								Salt: []byte("salt"),
							},
							KeySize: 32,
							Version: 0,
						}),
					},
					Params: &prfderpb.PrfBasedDeriverParams{
						DerivedKeyTemplate: &tinkpb.KeyTemplate{
							TypeUrl:          "type.googleapis.com/google.crypto.tink.AesGcmKey",
							OutputPrefixType: tinkpb.OutputPrefixType_TINK,
							Value: mustMarshal(t, &aesgcmpb.AesGcmKeyFormat{
								KeySize: 32,
							}),
						},
					},
				}),
			},
			params: mustCreateParameters(t, hkdfPRFParams, derivedKeyParametersTinkPrefix),
		},
		{
			name: "HKDF_no_prefix",
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
				Value: mustMarshal(t, &prfderpb.PrfBasedDeriverKeyFormat{
					PrfKeyTemplate: &tinkpb.KeyTemplate{
						TypeUrl:          "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
						OutputPrefixType: tinkpb.OutputPrefixType_RAW,
						Value: mustMarshal(t, &hkdfprfpb.HkdfPrfKeyFormat{
							Params: &hkdfprfpb.HkdfPrfParams{
								Hash: commonpb.HashType_SHA256,
								Salt: []byte("salt"),
							},
							KeySize: 32,
							Version: 0,
						}),
					},
					Params: &prfderpb.PrfBasedDeriverParams{
						DerivedKeyTemplate: &tinkpb.KeyTemplate{
							TypeUrl:          "type.googleapis.com/google.crypto.tink.AesGcmKey",
							OutputPrefixType: tinkpb.OutputPrefixType_RAW,
							Value: mustMarshal(t, &aesgcmpb.AesGcmKeyFormat{
								KeySize: 32,
							}),
						},
					},
				}),
			},
			params: mustCreateParameters(t, hkdfPRFParams, derivedKeyParametersNoPrefix),
		},
		{
			name: "HMAC_with_tink_prefix",
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				Value: mustMarshal(t, &prfderpb.PrfBasedDeriverKeyFormat{
					PrfKeyTemplate: &tinkpb.KeyTemplate{
						TypeUrl:          "type.googleapis.com/google.crypto.tink.HmacPrfKey",
						OutputPrefixType: tinkpb.OutputPrefixType_RAW,
						Value: mustMarshal(t, &hmacpb.HmacPrfKeyFormat{
							Params: &hmacpb.HmacPrfParams{
								Hash: commonpb.HashType_SHA256,
							},
							KeySize: 32,
							Version: 0,
						}),
					},
					Params: &prfderpb.PrfBasedDeriverParams{
						DerivedKeyTemplate: &tinkpb.KeyTemplate{
							TypeUrl:          "type.googleapis.com/google.crypto.tink.AesGcmKey",
							OutputPrefixType: tinkpb.OutputPrefixType_TINK,
							Value: mustMarshal(t, &aesgcmpb.AesGcmKeyFormat{
								KeySize: 32,
							}),
						},
					},
				}),
			},
			params: mustCreateParameters(t, hmacPRFParams, derivedKeyParametersTinkPrefix),
		},
		{
			name: "HMAC_no_prefix",
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
				Value: mustMarshal(t, &prfderpb.PrfBasedDeriverKeyFormat{
					PrfKeyTemplate: &tinkpb.KeyTemplate{
						TypeUrl:          "type.googleapis.com/google.crypto.tink.HmacPrfKey",
						OutputPrefixType: tinkpb.OutputPrefixType_RAW,
						Value: mustMarshal(t, &hmacpb.HmacPrfKeyFormat{
							Params: &hmacpb.HmacPrfParams{
								Hash: commonpb.HashType_SHA256,
							},
							KeySize: 32,
							Version: 0,
						}),
					},
					Params: &prfderpb.PrfBasedDeriverParams{
						DerivedKeyTemplate: &tinkpb.KeyTemplate{
							TypeUrl:          "type.googleapis.com/google.crypto.tink.AesGcmKey",
							OutputPrefixType: tinkpb.OutputPrefixType_RAW,
							Value: mustMarshal(t, &aesgcmpb.AesGcmKeyFormat{
								KeySize: 32,
							}),
						},
					},
				}),
			},
			params: mustCreateParameters(t, hmacPRFParams, derivedKeyParametersNoPrefix),
		},
	}
}

func TestParametersSerialization(t *testing.T) {
	for _, tc := range paramsParsingTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.SerializeParameters(tc.params)
			if err != nil {
				t.Errorf("protoserialization.SerializeParameters(%v) err = %p, want nil", tc.params, err)
			}
			if diff := cmp.Diff(tc.template, got, protocmp.Transform()); diff != "" {
				t.Errorf("protoserialization.SerializeParameters(%v) returned diff (-want +got):\n%s", tc.template, diff)
			}
		})
	}
}

func TestParametersParsing(t *testing.T) {
	for _, tc := range paramsParsingTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.ParseParameters(tc.template)
			if err != nil {
				t.Errorf("protoserialization.ParseParameters(%v) err = %p, want nil", tc.template, err)
			}
			if diff := cmp.Diff(tc.params, got, protocmp.Transform()); diff != "" {
				t.Errorf("protoserialization.ParseParameters(%v) returned diff (-want +got):\n%s", tc.template, diff)
			}
		})
	}
}

func TestParametersParsing_Fails(t *testing.T) {
	for _, tc := range []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{
			name: "invalid_aescmac_prf_key_format",
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				Value: mustMarshal(t, &prfderpb.PrfBasedDeriverKeyFormat{
					PrfKeyTemplate: &tinkpb.KeyTemplate{
						TypeUrl:          "type.googleapis.com/google.crypto.tink.AesCmacPrfKey",
						OutputPrefixType: tinkpb.OutputPrefixType_RAW,
						Value: mustMarshal(t, &aescmacprfpb.AesCmacPrfKeyFormat{
							KeySize: 1,
						}),
					},
					Params: &prfderpb.PrfBasedDeriverParams{
						DerivedKeyTemplate: &tinkpb.KeyTemplate{
							TypeUrl:          "type.googleapis.com/google.crypto.tink.AesGcmKey",
							OutputPrefixType: tinkpb.OutputPrefixType_TINK,
							Value: mustMarshal(t, &aesgcmpb.AesGcmKeyFormat{
								KeySize: 32,
							}),
						},
					},
				}),
			},
		},
		{
			name: "invalid_hkdf_prf_key_format",
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				Value: mustMarshal(t, &prfderpb.PrfBasedDeriverKeyFormat{
					PrfKeyTemplate: &tinkpb.KeyTemplate{
						TypeUrl:          "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
						OutputPrefixType: tinkpb.OutputPrefixType_RAW,
						Value: mustMarshal(t, &hkdfprfpb.HkdfPrfKeyFormat{
							Params: &hkdfprfpb.HkdfPrfParams{
								Hash: commonpb.HashType_UNKNOWN_HASH,
								Salt: []byte("salt"),
							},
							KeySize: 32,
						}),
					},
					Params: &prfderpb.PrfBasedDeriverParams{
						DerivedKeyTemplate: &tinkpb.KeyTemplate{
							TypeUrl:          "type.googleapis.com/google.crypto.tink.AesGcmKey",
							OutputPrefixType: tinkpb.OutputPrefixType_TINK,
							Value: mustMarshal(t, &aesgcmpb.AesGcmKeyFormat{
								KeySize: 32,
							}),
						},
					},
				}),
			},
		},
		{
			name: "invalid_hmac_prf_key_format",
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				Value: mustMarshal(t, &prfderpb.PrfBasedDeriverKeyFormat{
					PrfKeyTemplate: &tinkpb.KeyTemplate{
						TypeUrl:          "type.googleapis.com/google.crypto.tink.HmacPrfKey",
						OutputPrefixType: tinkpb.OutputPrefixType_RAW,
						Value: mustMarshal(t, &hmacpb.HmacPrfKeyFormat{
							Params: &hmacpb.HmacPrfParams{
								Hash: commonpb.HashType_UNKNOWN_HASH,
							},
							KeySize: 32,
						}),
					},
					Params: &prfderpb.PrfBasedDeriverParams{
						DerivedKeyTemplate: &tinkpb.KeyTemplate{
							TypeUrl:          "type.googleapis.com/google.crypto.tink.AesGcmKey",
							OutputPrefixType: tinkpb.OutputPrefixType_TINK,
							Value: mustMarshal(t, &aesgcmpb.AesGcmKeyFormat{
								KeySize: 32,
							}),
						},
					},
				}),
			},
		},
		{
			name: "invalid_derived_key_template",
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				Value: mustMarshal(t, &prfderpb.PrfBasedDeriverKeyFormat{
					PrfKeyTemplate: &tinkpb.KeyTemplate{
						TypeUrl:          "type.googleapis.com/google.crypto.tink.AesCmacPrfKey",
						OutputPrefixType: tinkpb.OutputPrefixType_RAW,
						Value: mustMarshal(t, &aescmacprfpb.AesCmacPrfKeyFormat{
							KeySize: 32,
						}),
					},
					Params: &prfderpb.PrfBasedDeriverParams{
						DerivedKeyTemplate: &tinkpb.KeyTemplate{
							TypeUrl:          "type.googleapis.com/google.crypto.tink.AesGcmKey",
							OutputPrefixType: tinkpb.OutputPrefixType_TINK,
							Value: mustMarshal(t, &aesgcmpb.AesGcmKeyFormat{
								KeySize: 1,
							}),
						},
					},
				}),
			},
		},
		{
			name: "invalid_output_prefix_type",
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
				OutputPrefixType: tinkpb.OutputPrefixType_UNKNOWN_PREFIX,
				Value: mustMarshal(t, &prfderpb.PrfBasedDeriverKeyFormat{
					PrfKeyTemplate: &tinkpb.KeyTemplate{
						TypeUrl:          "type.googleapis.com/google.crypto.tink.AesCmacPrfKey",
						OutputPrefixType: tinkpb.OutputPrefixType_RAW,
						Value: mustMarshal(t, &aescmacprfpb.AesCmacPrfKeyFormat{
							KeySize: 32,
						}),
					},
					Params: &prfderpb.PrfBasedDeriverParams{
						DerivedKeyTemplate: &tinkpb.KeyTemplate{
							TypeUrl:          "type.googleapis.com/google.crypto.tink.AesGcmKey",
							OutputPrefixType: tinkpb.OutputPrefixType_TINK,
							Value: mustMarshal(t, &aesgcmpb.AesGcmKeyFormat{
								KeySize: 32,
							}),
						},
					},
				}),
			},
		},
		{
			name: "inconsistent_output_prefix_type",
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
				Value: mustMarshal(t, &prfderpb.PrfBasedDeriverKeyFormat{
					PrfKeyTemplate: &tinkpb.KeyTemplate{
						TypeUrl:          "type.googleapis.com/google.crypto.tink.AesCmacPrfKey",
						OutputPrefixType: tinkpb.OutputPrefixType_RAW,
						Value: mustMarshal(t, &aescmacprfpb.AesCmacPrfKeyFormat{
							KeySize: 32,
						}),
					},
					Params: &prfderpb.PrfBasedDeriverParams{
						DerivedKeyTemplate: &tinkpb.KeyTemplate{
							TypeUrl:          "type.googleapis.com/google.crypto.tink.AesGcmKey",
							OutputPrefixType: tinkpb.OutputPrefixType_TINK,
							Value: mustMarshal(t, &aesgcmpb.AesGcmKeyFormat{
								KeySize: 32,
							}),
						},
					},
				}),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.ParseParameters(tc.template); err == nil {
				t.Errorf("protoserialization.ParseParameters(%v) err = nil, want error", tc.template)
			}
		})
	}
}
