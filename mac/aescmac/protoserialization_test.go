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

package aescmac_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/mac/aescmac"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testutil/testonlyinsecuresecretdataaccess"
	aescmacpb "github.com/tink-crypto/tink-go/v2/proto/aes_cmac_go_proto"
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

func TestParseKeyFails(t *testing.T) {
	serializedKey := mustMarshal(t, &aescmacpb.AesCmacKey{
		Version:  0,
		KeyValue: []byte("1234567890123456"),
		Params: &aescmacpb.AesCmacParams{
			TagSize: 16,
		},
	})
	serializedKeyWithInvalidKeySize := mustMarshal(t, &aescmacpb.AesCmacKey{
		Version:  0,
		KeyValue: []byte("0123"),
		Params: &aescmacpb.AesCmacParams{
			TagSize: 16,
		},
	})
	serializedKeyWithInvalidTagSize := mustMarshal(t, &aescmacpb.AesCmacKey{
		Version:  0,
		KeyValue: []byte("1234567890123456"),
		Params: &aescmacpb.AesCmacParams{
			TagSize: 2,
		},
	})
	serializedKeyWithInvalidVersion := mustMarshal(t, &aescmacpb.AesCmacKey{
		Version:  1,
		KeyValue: []byte("1234567890123456"),
		Params: &aescmacpb.AesCmacParams{
			TagSize: 16,
		},
	})
	for _, tc := range []struct {
		name             string
		keySerialization *protoserialization.KeySerialization
	}{
		{
			name: "invalid AES key size",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesCmacKey",
				Value:           serializedKeyWithInvalidKeySize,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "invalid TAG size",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesCmacKey",
				Value:           serializedKeyWithInvalidTagSize,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "invalid key proto serialization",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesCmacKey",
				Value:           []byte("invalid proto"),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "invalid key version",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesCmacKey",
				Value:           serializedKeyWithInvalidVersion,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "invalid output prefix type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesCmacKey",
				Value:           serializedKey,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_UNKNOWN_PREFIX, 12345),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.ParseKey(tc.keySerialization); err == nil {
				t.Errorf("p.ParseKey(%v) err = nil, want error", tc.keySerialization)
			}
		})
	}
}

type aesCMACSerializationTestCase struct {
	name             string
	key              *aescmac.Key
	keySerialization *protoserialization.KeySerialization
}

func aesCMACSerializationTestCases(t *testing.T) []aesCMACSerializationTestCase {
	tcs := []aesCMACSerializationTestCase{}
	for _, keySize := range []int{16, 32} {
		for _, variantAndPrefix := range []struct {
			variant          aescmac.Variant
			outputPrefixType tinkpb.OutputPrefixType
		}{
			{variant: aescmac.VariantTink, outputPrefixType: tinkpb.OutputPrefixType_TINK},
			{variant: aescmac.VariantCrunchy, outputPrefixType: tinkpb.OutputPrefixType_CRUNCHY},
			{variant: aescmac.VariantLegacy, outputPrefixType: tinkpb.OutputPrefixType_LEGACY},
			{variant: aescmac.VariantNoPrefix, outputPrefixType: tinkpb.OutputPrefixType_RAW},
		} {
			idRequirement := uint32(0)
			if variantAndPrefix.variant != aescmac.VariantNoPrefix {
				idRequirement = 0x01020304
			}
			keyBytes := slices.Repeat([]byte{0x01}, keySize)
			tcs = append(tcs, aesCMACSerializationTestCase{
				name: fmt.Sprintf("AES%d-CMAC-%s", keySize*8, variantAndPrefix.variant),
				key: mustCreateKey(t, secretdata.NewBytesFromData(keyBytes, testonlyinsecuresecretdataaccess.Token()), mustCreateParameters(t, aescmac.ParametersOpts{
					KeySizeInBytes: keySize,
					TagSizeInBytes: 16,
					Variant:        variantAndPrefix.variant}), idRequirement),
				keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
					TypeUrl: "type.googleapis.com/google.crypto.tink.AesCmacKey",
					Value: mustMarshal(t, &aescmacpb.AesCmacKey{
						Version:  0,
						KeyValue: keyBytes,
						Params: &aescmacpb.AesCmacParams{
							TagSize: 16,
						},
					}),
					KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
				}, variantAndPrefix.outputPrefixType, idRequirement),
			})
		}
	}
	return tcs
}

func TestParseKey(t *testing.T) {
	for _, tc := range aesCMACSerializationTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			gotKey, err := protoserialization.ParseKey(tc.keySerialization)
			if err != nil {
				t.Fatalf("protoserialization.ParseKey(%v) err = %v, want nil", tc.keySerialization, err)
			}
			if !gotKey.Equal(tc.key) {
				t.Errorf("key.Equal(wantKey) = false, want true")
			}
		})
	}
}

type testParams struct {
	hasIDRequirement bool
}

func (p *testParams) HasIDRequirement() bool { return p.hasIDRequirement }

func (p *testParams) Equal(params key.Parameters) bool {
	_, ok := params.(*testParams)
	return ok && p.hasIDRequirement == params.HasIDRequirement()
}

type testKey struct {
	keyBytes []byte
	id       uint32
	params   testParams
}

func (k *testKey) Parameters() key.Parameters { return &k.params }

func (k *testKey) Equal(other key.Key) bool {
	fallbackProtoKey, ok := other.(*testKey)
	if !ok {
		return false
	}
	return k.params.Equal(fallbackProtoKey.Parameters())
}

func (k *testKey) IDRequirement() (uint32, bool) { return k.id, k.params.HasIDRequirement() }

func TestSerializeKeyFails(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  key.Key
	}{
		{
			name: "key is nil",
			key:  nil,
		},
		{
			name: "key is not an AES key",
			key:  &testKey{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.SerializeKey(tc.key); err == nil {
				t.Errorf("protoserialization.SerializeKey() err = nil, want error")
			}
		})
	}
}

func TestSerializeKey(t *testing.T) {
	for _, tc := range aesCMACSerializationTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.SerializeKey(tc.key)
			if err != nil {
				t.Fatalf("protoserialization.SerializeKey(%v) err = %v, want nil", tc.key, err)
			}
			if !got.Equal(tc.keySerialization) {
				t.Errorf("got.Equal(tc.wantKeySerialization) = false, want true")
			}
		})
	}
}

func mustCreateKeyTemplate(t *testing.T, outputPrefixType tinkpb.OutputPrefixType, keySizeInBytes, tagSizeInBytes uint32) *tinkpb.KeyTemplate {
	t.Helper()
	return &tinkpb.KeyTemplate{
		TypeUrl:          "type.googleapis.com/google.crypto.tink.AesCmacKey",
		OutputPrefixType: outputPrefixType,
		Value: mustMarshal(t, &aescmacpb.AesCmacKeyFormat{
			KeySize: keySizeInBytes,
			Params: &aescmacpb.AesCmacParams{
				TagSize: tagSizeInBytes,
			},
		}),
	}
}

type parametersSerializationTestCase struct {
	name        string
	parameters  *aescmac.Parameters
	keyTemplate *tinkpb.KeyTemplate
}

func mustCreateParametersTestParameters(t *testing.T) []parametersSerializationTestCase {
	tcs := []parametersSerializationTestCase{}
	for _, keySize := range []int{16, 32} {
		for _, variantAndPrefix := range []struct {
			variant          aescmac.Variant
			outputPrefixType tinkpb.OutputPrefixType
		}{
			{variant: aescmac.VariantTink, outputPrefixType: tinkpb.OutputPrefixType_TINK},
			{variant: aescmac.VariantCrunchy, outputPrefixType: tinkpb.OutputPrefixType_CRUNCHY},
			{variant: aescmac.VariantLegacy, outputPrefixType: tinkpb.OutputPrefixType_LEGACY},
			{variant: aescmac.VariantNoPrefix, outputPrefixType: tinkpb.OutputPrefixType_RAW},
		} {
			tcs = append(tcs, parametersSerializationTestCase{
				name: fmt.Sprintf("AES%d-CMAC-%s", keySize*8, variantAndPrefix.variant),
				parameters: mustCreateParameters(t, aescmac.ParametersOpts{
					KeySizeInBytes: keySize,
					TagSizeInBytes: 16,
					Variant:        variantAndPrefix.variant,
				}),
				keyTemplate: &tinkpb.KeyTemplate{
					TypeUrl:          "type.googleapis.com/google.crypto.tink.AesCmacKey",
					OutputPrefixType: variantAndPrefix.outputPrefixType,
					Value: mustMarshal(t, &aescmacpb.AesCmacKeyFormat{
						KeySize: uint32(keySize),
						Params: &aescmacpb.AesCmacParams{
							TagSize: 16,
						},
					}),
				},
			})
		}
	}
	return tcs
}

func TestSerializeParameters(t *testing.T) {
	for _, tc := range mustCreateParametersTestParameters(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.SerializeParameters(tc.parameters)
			if err != nil {
				t.Fatalf("protoserialization.SerializeParameters(%v) err = %v, want nil", tc.parameters, err)
			}
			if diff := cmp.Diff(tc.keyTemplate, got, protocmp.Transform()); diff != "" {
				t.Errorf("protoserialization.SerializeParameters(%v) returned unexpected diff (-want +got):\n%s", tc.parameters, diff)
			}
		})
	}
}

func TestParseParameters(t *testing.T) {
	for _, tc := range mustCreateParametersTestParameters(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.ParseParameters(tc.keyTemplate)
			if err != nil {
				t.Fatalf("protoserialization.ParseParameters(%v) err = %v, want nil", tc.keyTemplate, err)
			}
			if diff := cmp.Diff(tc.parameters, got); diff != "" {
				t.Errorf("protoserialization.ParseParameters(%v) returned unexpected diff (-want +got):\n%s", tc.keyTemplate, diff)
			}
		})
	}
}

func TestParseParametersFailsWithWrongKeyTemplate(t *testing.T) {
	for _, tc := range []struct {
		name        string
		keyTemplate *tinkpb.KeyTemplate
	}{
		{
			name:        "empty",
			keyTemplate: &tinkpb.KeyTemplate{},
		},
		{
			name: "empty format",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.AesCmacKey",
				Value:            mustMarshal(t, &aescmacpb.AesCmacKeyFormat{}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "invalid format value",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.AesCmacKey",
				Value:            []byte("invalid format"),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "invalid tag size",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesCmacKey",
				Value: mustMarshal(t, &aescmacpb.AesCmacKeyFormat{
					KeySize: 16,
					Params: &aescmacpb.AesCmacParams{
						TagSize: 2,
					},
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "invalid key size",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesCmacKey",
				Value: mustMarshal(t, &aescmacpb.AesCmacKeyFormat{
					KeySize: 10,
					Params: &aescmacpb.AesCmacParams{
						TagSize: 16,
					},
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "unknown output prefix type",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesCmacKey",
				Value: mustMarshal(t, &aescmacpb.AesCmacKeyFormat{
					KeySize: 16,
					Params: &aescmacpb.AesCmacParams{
						TagSize: 16,
					},
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_UNKNOWN_PREFIX,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.ParseParameters(tc.keyTemplate); err == nil {
				t.Errorf("protoserialization.ParseParameters(%v) err = nil, want error", tc.keyTemplate)
			}
		})
	}
}
