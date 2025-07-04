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

package aesctrhmac_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/streamingaead/aesctrhmac"
	streamaeadpb "github.com/tink-crypto/tink-go/v2/proto/aes_ctr_hmac_streaming_go_proto"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	hmacpb "github.com/tink-crypto/tink-go/v2/proto/hmac_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func mustMarshal(t *testing.T, p proto.Message) []byte {
	t.Helper()
	data, err := proto.Marshal(p)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	return data
}

type keyParsingTestCase struct {
	name             string
	keySerialization *protoserialization.KeySerialization
	key              *aesctrhmac.Key
}

func testCases(t *testing.T) []*keyParsingTestCase {
	t.Helper()

	keyBytes := []byte("0123456789012345678901234567890101234567890123456789012345678901")

	var testCases []*keyParsingTestCase
	keySizes := []int{16, 32}
	segmentSizes := []int32{4096, 8192}

	for _, keySize := range keySizes {
		for _, hashType := range []struct {
			hashType      aesctrhmac.HashType
			protoHashType commonpb.HashType
		}{
			{aesctrhmac.SHA1, commonpb.HashType_SHA1},
			{aesctrhmac.SHA256, commonpb.HashType_SHA256},
			{aesctrhmac.SHA512, commonpb.HashType_SHA512},
		} {
			for _, hmacHashType := range []struct {
				hashType      aesctrhmac.HashType
				protoHashType commonpb.HashType
				tagSize       int
			}{
				{aesctrhmac.SHA1, commonpb.HashType_SHA1, 20},
				{aesctrhmac.SHA256, commonpb.HashType_SHA256, 32},
				{aesctrhmac.SHA512, commonpb.HashType_SHA512, 64},
			} {
				for _, segmentSize := range segmentSizes {
					params, err := aesctrhmac.NewParameters(aesctrhmac.ParametersOpts{
						KeySizeInBytes:        keySize,
						DerivedKeySizeInBytes: keySize,
						HkdfHashType:          hashType.hashType,
						HmacHashType:          hmacHashType.hashType,
						HmacTagSizeInBytes:    hmacHashType.tagSize,
						SegmentSizeInBytes:    segmentSize,
					})
					if err != nil {
						t.Fatalf("aesctrhmac.NewParameters() err = %v, want nil", err)
					}
					keySecretDataBytes := secretdata.NewBytesFromData(keyBytes[:keySize], insecuresecretdataaccess.Token{})
					k, err := aesctrhmac.NewKey(params, keySecretDataBytes)
					if err != nil {
						t.Fatalf("aesctrhmac.NewKey() err = %v, want nil", err)
					}

					serializedKey := mustMarshal(t, &streamaeadpb.AesCtrHmacStreamingKey{
						Version:  0,
						KeyValue: keySecretDataBytes.Data(insecuresecretdataaccess.Token{}),
						Params: &streamaeadpb.AesCtrHmacStreamingParams{
							HkdfHashType:          hashType.protoHashType,
							DerivedKeySize:        uint32(keySize),
							CiphertextSegmentSize: uint32(segmentSize),
							HmacParams: &hmacpb.HmacParams{
								Hash:    hmacHashType.protoHashType,
								TagSize: uint32(hmacHashType.tagSize),
							},
						},
					})
					keyData := &tinkpb.KeyData{
						TypeUrl:         "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
						Value:           serializedKey,
						KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					}
					ks, err := protoserialization.NewKeySerialization(keyData, tinkpb.OutputPrefixType_RAW, 0)
					if err != nil {
						t.Fatalf("protoserialization.NewKeySerialization() err = %v, want nil", err)
					}
					testCases = append(testCases, &keyParsingTestCase{
						name:             fmt.Sprintf("keySize:%d,derivedKeySize:%d,hkdfHashType:%s,hmacHashType:%s,tagSize:%d,segmentSize:%d", keySize, keySize, hashType.hashType, hmacHashType.hashType, hmacHashType.tagSize, segmentSize),
						keySerialization: ks,
						key:              k,
					})
				}
			}
		}
	}
	return testCases
}

func TestParseKey(t *testing.T) {
	for _, tc := range testCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			gotKey, err := protoserialization.ParseKey(tc.keySerialization)
			if err != nil {
				t.Fatalf("protoserialization.ParseKey() err = %v, want nil", err)
			}
			if diff := cmp.Diff(tc.key, gotKey, cmp.AllowUnexported(aesctrhmac.Key{}, aesctrhmac.Parameters{})); diff != "" {
				t.Errorf("parsed key is not equal to original key. diff (-want +got):\n%s", diff)
			}
		})
	}
}

func mustCreateProtoSerialization(t *testing.T, keyData *tinkpb.KeyData, outputPrefixType tinkpb.OutputPrefixType, idRequirement uint32) *protoserialization.KeySerialization {
	t.Helper()
	ks, err := protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
	if err != nil {
		t.Fatalf("protoserialization.NewKeySerialization() err = %v, want nil", err)
	}
	return ks
}

func TestParseKey_Fails(t *testing.T) {
	for _, tc := range []struct {
		name             string
		keyData          *tinkpb.KeyData
		outputPrefixType tinkpb.OutputPrefixType
		keyID            uint32
	}{
		{
			name: "invalid key data value",
			keyData: &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
				Value:           []byte("invalid proto"),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_RAW,
			keyID:            0,
		},
		{
			name: "wrong key material type",
			keyData: &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
				Value: mustMarshal(t, &streamaeadpb.AesCtrHmacStreamingKey{
					Version:  0,
					KeyValue: []byte("0123456789012345"),
					Params: &streamaeadpb.AesCtrHmacStreamingParams{
						HkdfHashType:          commonpb.HashType_SHA256,
						DerivedKeySize:        16,
						CiphertextSegmentSize: 4096,
						HmacParams: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 16,
						},
					},
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_RAW,
			keyID:            0,
		},
		{
			name: "invalid version",
			keyData: &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
				Value: mustMarshal(t, &streamaeadpb.AesCtrHmacStreamingKey{
					Version:  1,
					KeyValue: []byte("0123456789012345"),
					Params: &streamaeadpb.AesCtrHmacStreamingParams{
						HkdfHashType:          commonpb.HashType_SHA256,
						DerivedKeySize:        16,
						CiphertextSegmentSize: 4096,
						HmacParams: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 16,
						},
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_RAW,
			keyID:            0,
		},
		{
			name: "invalid_key_value",
			keyData: &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
				Value: mustMarshal(t, &streamaeadpb.AesCtrHmacStreamingKey{
					Version:  0,
					KeyValue: []byte("01234567890123"), // Key size should be 16 or 32
					Params: &streamaeadpb.AesCtrHmacStreamingParams{
						HkdfHashType:          commonpb.HashType_SHA256,
						DerivedKeySize:        16,
						CiphertextSegmentSize: 4096,
						HmacParams: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 16,
						},
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_RAW,
			keyID:            0,
		},
		{
			name: "invalid_derived_key_size",
			keyData: &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
				Value: mustMarshal(t, &streamaeadpb.AesCtrHmacStreamingKey{
					Version:  0,
					KeyValue: []byte("0123456789012345"),
					Params: &streamaeadpb.AesCtrHmacStreamingParams{
						HkdfHashType:          commonpb.HashType_SHA256,
						DerivedKeySize:        12, // Derived key size should be 16 or 32
						CiphertextSegmentSize: 4096,
						HmacParams: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 16,
						},
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_RAW,
			keyID:            0,
		},
		{
			name: "invalid_segment_size",
			keyData: &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
				Value: mustMarshal(t, &streamaeadpb.AesCtrHmacStreamingKey{
					Version:  0,
					KeyValue: []byte("0123456789012345"),
					Params: &streamaeadpb.AesCtrHmacStreamingParams{
						HkdfHashType:          commonpb.HashType_SHA256,
						DerivedKeySize:        16,
						CiphertextSegmentSize: 10,
						HmacParams: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 16,
						},
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_RAW,
			keyID:            0,
		},
		{
			name: "invalid_hmac_tag_size",
			keyData: &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
				Value: mustMarshal(t, &streamaeadpb.AesCtrHmacStreamingKey{
					Version:  0,
					KeyValue: []byte("0123456789012345"),
					Params: &streamaeadpb.AesCtrHmacStreamingParams{
						HkdfHashType:          commonpb.HashType_SHA256,
						DerivedKeySize:        16,
						CiphertextSegmentSize: 4096,
						HmacParams: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 2, // tag size should be at least 10.
						},
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_RAW,
			keyID:            0,
		},
		{
			name: "invalid_hkdf_hash_type",
			keyData: &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
				Value: mustMarshal(t, &streamaeadpb.AesCtrHmacStreamingKey{
					Version:  0,
					KeyValue: []byte("0123456789012345"),
					Params: &streamaeadpb.AesCtrHmacStreamingParams{
						HkdfHashType:          commonpb.HashType_UNKNOWN_HASH,
						DerivedKeySize:        16,
						CiphertextSegmentSize: 4096,
						HmacParams: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 32,
						},
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_RAW,
			keyID:            0,
		},
		{
			name: "invalid_hmac_hash_type",
			keyData: &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
				Value: mustMarshal(t, &streamaeadpb.AesCtrHmacStreamingKey{
					Version:  0,
					KeyValue: []byte("0123456789012345"),
					Params: &streamaeadpb.AesCtrHmacStreamingParams{
						HkdfHashType:          commonpb.HashType_SHA256,
						DerivedKeySize:        16,
						CiphertextSegmentSize: 4096,
						HmacParams: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_UNKNOWN_HASH,
							TagSize: 32,
						},
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_RAW,
			keyID:            0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keySerialization, err := protoserialization.NewKeySerialization(tc.keyData, tc.outputPrefixType, tc.keyID)
			if err != nil {
				t.Fatalf("protoserialization.NewKeySerialization(%v, %v, %v) err = %v, want nil", tc.keyData, tc.outputPrefixType, tc.keyID, err)
			}
			if _, err := protoserialization.ParseKey(keySerialization); err == nil {
				t.Errorf("protoserialization.ParseKey(%v) err = nil, want non-nil", keySerialization)
			}
		})
	}
}

func TestSerializeKey(t *testing.T) {
	for _, tc := range testCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			gotSerialization, err := protoserialization.SerializeKey(tc.key)
			if err != nil {
				t.Fatalf("protoserialization.SerializeKey() err = %v, want nil", err)
			}
			if diff := cmp.Diff(tc.keySerialization, gotSerialization, protocmp.Transform()); diff != "" {
				t.Errorf("serialized key is not equal to original. diff: %s", diff)
			}
		})
	}
}

func TestSerializeKey_Fails(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  key.Key
	}{
		{
			name: "nil key",
			key:  nil,
		},
		{
			name: "key with wrong parameters type",
			key:  &stubKey{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.SerializeKey(tc.key); err == nil {
				t.Error("SerializeKey() err = nil, want non-nil")
			}
		})
	}
}

type parametersTestCase struct {
	name        string
	parameters  *aesctrhmac.Parameters
	keyTemplate *tinkpb.KeyTemplate
}

func parameterTestCases(t *testing.T) []*parametersTestCase {
	t.Helper()
	var testCases []*parametersTestCase
	keySizes := []int{16, 32}
	segmentSizes := []int32{4096, 8192}

	for _, keySize := range keySizes {
		for _, hashType := range []struct {
			hashType      aesctrhmac.HashType
			protoHashType commonpb.HashType
		}{
			{aesctrhmac.SHA1, commonpb.HashType_SHA1},
			{aesctrhmac.SHA256, commonpb.HashType_SHA256},
			{aesctrhmac.SHA512, commonpb.HashType_SHA512},
		} {
			for _, hmacHashType := range []struct {
				hashType      aesctrhmac.HashType
				protoHashType commonpb.HashType
				tagSize       int
			}{
				{aesctrhmac.SHA1, commonpb.HashType_SHA1, 20},
				{aesctrhmac.SHA256, commonpb.HashType_SHA256, 32},
				{aesctrhmac.SHA512, commonpb.HashType_SHA512, 64},
			} {
				for _, segmentSize := range segmentSizes {
					params, err := aesctrhmac.NewParameters(aesctrhmac.ParametersOpts{
						KeySizeInBytes:        keySize,
						DerivedKeySizeInBytes: keySize,
						HkdfHashType:          hashType.hashType,
						HmacHashType:          hmacHashType.hashType,
						HmacTagSizeInBytes:    hmacHashType.tagSize,
						SegmentSizeInBytes:    segmentSize,
					})
					if err != nil {
						t.Fatalf("aesctrhmac.NewParameters() err = %v, want nil", err)
					}

					keyTemplate := &tinkpb.KeyTemplate{
						TypeUrl: "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
						Value: mustMarshal(t, &streamaeadpb.AesCtrHmacStreamingKeyFormat{
							Version: 0,
							Params: &streamaeadpb.AesCtrHmacStreamingParams{
								HkdfHashType:          hashType.protoHashType,
								DerivedKeySize:        uint32(keySize),
								CiphertextSegmentSize: uint32(segmentSize),
								HmacParams: &hmacpb.HmacParams{
									Hash:    hmacHashType.protoHashType,
									TagSize: uint32(hmacHashType.tagSize),
								},
							},
							KeySize: uint32(keySize),
						}),
						OutputPrefixType: tinkpb.OutputPrefixType_RAW,
					}

					testCases = append(testCases, &parametersTestCase{
						name:        fmt.Sprintf("keySize:%d,derivedKeySize:%d,hkdfHashType:%s,hmacHashType:%s,tagSize:%d,segmentSize:%d", keySize, keySize, hashType.hashType, hmacHashType.hashType, hmacHashType.tagSize, segmentSize),
						parameters:  params,
						keyTemplate: keyTemplate,
					})
				}
			}
		}
	}
	return testCases
}

func TestParseParameters(t *testing.T) {
	for _, tc := range parameterTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			gotParams, err := protoserialization.ParseParameters(tc.keyTemplate)
			if err != nil {
				t.Fatalf("protoserialization.ParseParameters() err = %v, want nil", err)
			}
			if diff := cmp.Diff(tc.parameters, gotParams); diff != "" {
				t.Errorf("parsed parameters are not equal to original parameters. diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseParameters_Fails(t *testing.T) {
	for _, tc := range []struct {
		name        string
		keyTemplate *tinkpb.KeyTemplate
		keyFormat   proto.Message
	}{
		{
			name: "invalid_derived_key_size",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
				Value: mustMarshal(t, &streamaeadpb.AesCtrHmacStreamingKeyFormat{
					Params: &streamaeadpb.AesCtrHmacStreamingParams{
						HkdfHashType:          commonpb.HashType_SHA256,
						DerivedKeySize:        12, // Derived key size should be 16 or 32
						CiphertextSegmentSize: 4096,
						HmacParams: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 16,
						},
					},
					KeySize: 16,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			name: "invalid_key_size",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
				Value: mustMarshal(t, &streamaeadpb.AesCtrHmacStreamingKeyFormat{
					Params: &streamaeadpb.AesCtrHmacStreamingParams{
						HkdfHashType:          commonpb.HashType_SHA256,
						DerivedKeySize:        12, // Derived key size should be 16 or 32
						CiphertextSegmentSize: 4096,
						HmacParams: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 16,
						},
					},
					KeySize: 12, // Key size should be 16 or 32
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			name: "invalid_segment_size",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
				Value: mustMarshal(t, &streamaeadpb.AesCtrHmacStreamingKeyFormat{
					Params: &streamaeadpb.AesCtrHmacStreamingParams{
						HkdfHashType:          commonpb.HashType_SHA256,
						DerivedKeySize:        16,
						CiphertextSegmentSize: 10,
						HmacParams: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 16,
						},
					},
					KeySize: 16,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			name: "invalid_hmac_tag_size",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
				Value: mustMarshal(t, &streamaeadpb.AesCtrHmacStreamingKeyFormat{
					Params: &streamaeadpb.AesCtrHmacStreamingParams{
						HkdfHashType:          commonpb.HashType_SHA256,
						DerivedKeySize:        16,
						CiphertextSegmentSize: 4096,
						HmacParams: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 2, // tag size should be at least 10.
						},
					},
					KeySize: 16,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			name: "invalid_hkdf_hash_type",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
				Value: mustMarshal(t, &streamaeadpb.AesCtrHmacStreamingKeyFormat{
					Params: &streamaeadpb.AesCtrHmacStreamingParams{
						HkdfHashType:          commonpb.HashType_UNKNOWN_HASH,
						DerivedKeySize:        16,
						CiphertextSegmentSize: 4096,
						HmacParams: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 16,
						},
					},
					KeySize: 16,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			name: "invalid_version",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
				Value: mustMarshal(t, &streamaeadpb.AesCtrHmacStreamingKeyFormat{
					Version: 1,
					Params: &streamaeadpb.AesCtrHmacStreamingParams{
						HkdfHashType:          commonpb.HashType_SHA256,
						DerivedKeySize:        16,
						CiphertextSegmentSize: 4096,
						HmacParams: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 16,
						},
					},
					KeySize: 16,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			name: "invalid_hmac_hash_type",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
				Value: mustMarshal(t, &streamaeadpb.AesCtrHmacStreamingKeyFormat{
					Params: &streamaeadpb.AesCtrHmacStreamingParams{
						HkdfHashType:          commonpb.HashType_SHA256,
						DerivedKeySize:        16,
						CiphertextSegmentSize: 4096,
						HmacParams: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_UNKNOWN_HASH,
							TagSize: 32,
						},
					},
					KeySize: 16,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			name: "invalid_output_prefix_type",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
				Value: mustMarshal(t, &streamaeadpb.AesCtrHmacStreamingKeyFormat{
					Params: &streamaeadpb.AesCtrHmacStreamingParams{
						HkdfHashType:          commonpb.HashType_SHA256,
						DerivedKeySize:        16,
						CiphertextSegmentSize: 4096,
						HmacParams: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 32,
						},
					},
					KeySize: 16,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK, // Output prefix type should be RAW.
			},
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
	for _, tc := range parameterTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.SerializeParameters(tc.parameters)
			if err != nil {
				t.Fatalf("protoserialization.SerializeParameters() err = %v, want nil", err)
			}
			if diff := cmp.Diff(tc.keyTemplate, got, protocmp.Transform()); diff != "" {
				t.Errorf("serialized parameters are not equal to original. diff: %s", diff)
			}
		})
	}
}
