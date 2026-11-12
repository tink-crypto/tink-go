// Copyright 2026 Google LLC
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

package keytest_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/internal/keytest"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	testonlypb "github.com/tink-crypto/tink-go/v2/proto/test_only_key_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const testOnlyKeyTypeURL = "type.googleapis.com/google.crypto.tink.TestOnlyKey"

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

func mustCreateParameters(t *testing.T, variant keytest.Variant) *keytest.Parameters {
	t.Helper()
	params, err := keytest.NewParameters(variant)
	if err != nil {
		t.Fatalf("keytest.NewParameters(%v) err = %v, want nil", variant, err)
	}
	return params
}

func TestSerializeKey(t *testing.T) {
	keyData := &tinkpb.KeyData{
		TypeUrl: testOnlyKeyTypeURL,
		Value: mustMarshal(t, &testonlypb.TestOnlyKey{
			Version:  0,
			KeyValue: key128Bits,
		}),
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}
	for _, tc := range []struct {
		name                 string
		key                  *keytest.Key
		wantKeySerialization *protoserialization.KeySerialization
	}{
		{
			name:                 "TINK",
			key:                  mustCreateKey(t, keytest.VariantTink, 12345, key128Bits),
			wantKeySerialization: mustCreateKeySerialization(t, keyData, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name:                 "CRUNCHY",
			key:                  mustCreateKey(t, keytest.VariantCrunchy, 12345, key128Bits),
			wantKeySerialization: mustCreateKeySerialization(t, keyData, tinkpb.OutputPrefixType_CRUNCHY, 12345),
		},
		{
			name:                 "NO_PREFIX",
			key:                  mustCreateKey(t, keytest.VariantNoPrefix, 0, key128Bits),
			wantKeySerialization: mustCreateKeySerialization(t, keyData, tinkpb.OutputPrefixType_RAW, 0),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.SerializeKey(tc.key)
			if err != nil {
				t.Fatalf("protoserialization.SerializeKey(%v) err = %v, want nil", tc.key, err)
			}
			if !got.Equal(tc.wantKeySerialization) {
				t.Errorf("protoserialization.SerializeKey(%v) = %v, want %v", tc.key, got, tc.wantKeySerialization)
			}
		})
	}
}

func TestSerializeKeyFailsWithInvalidKey(t *testing.T) {
	k := &keytest.Key{}
	if _, err := protoserialization.SerializeKey(k); err == nil {
		t.Errorf("protoserialization.SerializeKey(%v) err = nil, want error", k)
	}
}

func TestParseKey(t *testing.T) {
	keyData := &tinkpb.KeyData{
		TypeUrl: testOnlyKeyTypeURL,
		Value: mustMarshal(t, &testonlypb.TestOnlyKey{
			Version:  0,
			KeyValue: key128Bits,
		}),
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}
	for _, tc := range []struct {
		name             string
		keySerialization *protoserialization.KeySerialization
		wantKey          *keytest.Key
	}{
		{
			name:             "TINK",
			keySerialization: mustCreateKeySerialization(t, keyData, tinkpb.OutputPrefixType_TINK, 12345),
			wantKey:          mustCreateKey(t, keytest.VariantTink, 12345, key128Bits),
		},
		{
			name:             "CRUNCHY",
			keySerialization: mustCreateKeySerialization(t, keyData, tinkpb.OutputPrefixType_CRUNCHY, 12345),
			wantKey:          mustCreateKey(t, keytest.VariantCrunchy, 12345, key128Bits),
		},
		{
			name:             "LEGACY",
			keySerialization: mustCreateKeySerialization(t, keyData, tinkpb.OutputPrefixType_LEGACY, 12345),
			wantKey:          mustCreateKey(t, keytest.VariantCrunchy, 12345, key128Bits),
		},
		{
			name:             "RAW",
			keySerialization: mustCreateKeySerialization(t, keyData, tinkpb.OutputPrefixType_RAW, 0),
			wantKey:          mustCreateKey(t, keytest.VariantNoPrefix, 0, key128Bits),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.ParseKey(tc.keySerialization)
			if err != nil {
				t.Fatalf("protoserialization.ParseKey(%v) err = %v, want nil", tc.keySerialization, err)
			}
			if !got.Equal(tc.wantKey) {
				t.Errorf("protoserialization.ParseKey(%v) = %v, want %v", tc.keySerialization, got, tc.wantKey)
			}
		})
	}
}

func TestSerializeAndParseKey(t *testing.T) {
	for _, tc := range keyTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			k := mustCreateKey(t, tc.variant, tc.keyID, tc.keyBytes)
			keySerialization, err := protoserialization.SerializeKey(k)
			if err != nil {
				t.Fatalf("protoserialization.SerializeKey(%v) err = %v, want nil", k, err)
			}
			got, err := protoserialization.ParseKey(keySerialization)
			if err != nil {
				t.Fatalf("protoserialization.ParseKey(%v) err = %v, want nil", keySerialization, err)
			}
			if !got.Equal(k) {
				t.Errorf("protoserialization.ParseKey(%v) = %v, want %v", keySerialization, got, k)
			}
		})
	}
}

func TestParseKeyFails(t *testing.T) {
	serializedKey := mustMarshal(t, &testonlypb.TestOnlyKey{
		Version:  0,
		KeyValue: key128Bits,
	})
	for _, tc := range []struct {
		name             string
		keyData          *tinkpb.KeyData
		outputPrefixType tinkpb.OutputPrefixType
		keyID            uint32
	}{
		{
			name: "wrong key material type",
			keyData: &tinkpb.KeyData{
				TypeUrl:         testOnlyKeyTypeURL,
				Value:           serializedKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "wrong version",
			keyData: &tinkpb.KeyData{
				TypeUrl: testOnlyKeyTypeURL,
				Value: mustMarshal(t, &testonlypb.TestOnlyKey{
					Version:  1,
					KeyValue: key128Bits,
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "key too short",
			keyData: &tinkpb.KeyData{
				TypeUrl: testOnlyKeyTypeURL,
				Value: mustMarshal(t, &testonlypb.TestOnlyKey{
					Version:  0,
					KeyValue: key128Bits[:15],
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "key too long",
			keyData: &tinkpb.KeyData{
				TypeUrl: testOnlyKeyTypeURL,
				Value: mustMarshal(t, &testonlypb.TestOnlyKey{
					Version:  0,
					KeyValue: key256Bits,
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "unknown output prefix type",
			keyData: &tinkpb.KeyData{
				TypeUrl:         testOnlyKeyTypeURL,
				Value:           serializedKey,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_UNKNOWN_PREFIX,
			keyID:            12345,
		},
		{
			name: "zero key ID with TINK output prefix type",
			keyData: &tinkpb.KeyData{
				TypeUrl:         testOnlyKeyTypeURL,
				Value:           serializedKey,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            0,
		},
		{
			name: "malformed proto key",
			keyData: &tinkpb.KeyData{
				TypeUrl:         testOnlyKeyTypeURL,
				Value:           []byte("invalid proto"),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keySerialization := mustCreateKeySerialization(t, tc.keyData, tc.outputPrefixType, tc.keyID)
			if _, err := protoserialization.ParseKey(keySerialization); err == nil {
				t.Errorf("protoserialization.ParseKey(%v) err = nil, want error", keySerialization)
			}
		})
	}
}

func mustCreateKeyTemplate(t *testing.T, outputPrefixType tinkpb.OutputPrefixType, keySizeInBytes uint32) *tinkpb.KeyTemplate {
	t.Helper()
	return &tinkpb.KeyTemplate{
		TypeUrl:          testOnlyKeyTypeURL,
		OutputPrefixType: outputPrefixType,
		Value:            mustMarshal(t, &testonlypb.TestOnlyKeyFormat{KeySize: keySizeInBytes}),
	}
}

func TestSerializeParameters(t *testing.T) {
	for _, tc := range []struct {
		name            string
		parameters      *keytest.Parameters
		wantKeyTemplate *tinkpb.KeyTemplate
	}{
		{
			name:            "TINK",
			parameters:      mustCreateParameters(t, keytest.VariantTink),
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_TINK, 16),
		},
		{
			name:            "CRUNCHY",
			parameters:      mustCreateParameters(t, keytest.VariantCrunchy),
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_CRUNCHY, 16),
		},
		{
			name:            "NO_PREFIX",
			parameters:      mustCreateParameters(t, keytest.VariantNoPrefix),
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_RAW, 16),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.SerializeParameters(tc.parameters)
			if err != nil {
				t.Fatalf("protoserialization.SerializeParameters(%v) err = %v, want nil", tc.parameters, err)
			}
			if diff := cmp.Diff(tc.wantKeyTemplate, got, protocmp.Transform()); diff != "" {
				t.Errorf("protoserialization.SerializeParameters(%v) returned unexpected diff (-want +got):\n%s", tc.parameters, diff)
			}
		})
	}
}

func TestSerializeParametersFailsWithInvalidParameters(t *testing.T) {
	params := &keytest.Parameters{}
	if _, err := protoserialization.SerializeParameters(params); err == nil {
		t.Errorf("protoserialization.SerializeParameters(%v) err = nil, want error", params)
	}
}

func TestParseParameters(t *testing.T) {
	for _, tc := range []struct {
		name           string
		keyTemplate    *tinkpb.KeyTemplate
		wantParameters *keytest.Parameters
	}{
		{
			name:           "TINK",
			keyTemplate:    mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_TINK, 16),
			wantParameters: mustCreateParameters(t, keytest.VariantTink),
		},
		{
			name:           "CRUNCHY",
			keyTemplate:    mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_CRUNCHY, 16),
			wantParameters: mustCreateParameters(t, keytest.VariantCrunchy),
		},
		{
			name:           "LEGACY",
			keyTemplate:    mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_LEGACY, 16),
			wantParameters: mustCreateParameters(t, keytest.VariantCrunchy),
		},
		{
			name:           "RAW",
			keyTemplate:    mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_RAW, 16),
			wantParameters: mustCreateParameters(t, keytest.VariantNoPrefix),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.ParseParameters(tc.keyTemplate)
			if err != nil {
				t.Fatalf("protoserialization.ParseParameters(%v) err = %v, want nil", tc.keyTemplate, err)
			}
			if !got.Equal(tc.wantParameters) {
				t.Errorf("protoserialization.ParseParameters(%v) = %v, want %v", tc.keyTemplate, got, tc.wantParameters)
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
			name:        "key size not set",
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_TINK, 0),
		},
		{
			name:        "wrong key size",
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_TINK, 32),
		},
		{
			name:        "unknown output prefix type",
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_UNKNOWN_PREFIX, 16),
		},
		{
			name: "malformed proto format",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl:          testOnlyKeyTypeURL,
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				Value:            []byte("invalid format"),
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
