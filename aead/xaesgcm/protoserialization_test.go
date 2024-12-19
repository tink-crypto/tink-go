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

package xaesgcm_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/aead/xaesgcm"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	xaesgcmpb "github.com/tink-crypto/tink-go/v2/proto/x_aes_gcm_go_proto"
)

func mustMarshalProto(t *testing.T, message proto.Message) []byte {
	t.Helper()
	serializedMessage, err := proto.Marshal(message)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", message, err)
	}
	return serializedMessage
}

func TestParseKeyFails(t *testing.T) {
	validXAESGCMKey := &xaesgcmpb.XAesGcmKey{
		Version:  0,
		KeyValue: []byte("12345678901234561234567890123456"),
		Params: &xaesgcmpb.XAesGcmParams{
			SaltSize: 12,
		},
	}
	for _, tc := range []struct {
		name             string
		keyData          *tinkpb.KeyData
		outputPrefixType tinkpb.OutputPrefixType
		keyID            uint32
	}{
		{
			name: "invalid key size",
			keyData: &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.XAesGcmKey",
				Value: mustMarshalProto(t, &xaesgcmpb.XAesGcmKey{
					Version:  0,
					KeyValue: []byte("0123"),
					Params: &xaesgcmpb.XAesGcmParams{
						SaltSize: 12,
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            0x11223344,
		},
		{
			name: "invalid salt length",
			keyData: &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.XAesGcmKey",
				Value: mustMarshalProto(t, &xaesgcmpb.XAesGcmKey{
					Version:  0,
					KeyValue: []byte("12345678901234561234567890123456"),
					Params: &xaesgcmpb.XAesGcmParams{
						SaltSize: 16,
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            0x11223344,
		},
		{
			name: "invalid key proto serialization",
			keyData: &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.XAesGcmKey",
				Value:           []byte("invalid proto"),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            0x11223344,
		},
		{
			name: "invalid key version",
			keyData: &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.XAesGcmKey",
				Value: mustMarshalProto(t, &xaesgcmpb.XAesGcmKey{
					Version:  1,
					KeyValue: []byte("12345678901234561234567890123456"),
					Params: &xaesgcmpb.XAesGcmParams{
						SaltSize: 12,
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            0x11223344,
		},
		{
			name: "invalid key material type",
			keyData: &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.XAesGcmKey",
				Value:           mustMarshalProto(t, validXAESGCMKey),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            0x11223344,
		},
		{
			name: "invalid output prefix type",
			keyData: &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.XAesGcmKey",
				Value:           mustMarshalProto(t, validXAESGCMKey),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_UNKNOWN_PREFIX,
			keyID:            0x11223344,
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

func mustCreateKeySerialization(t *testing.T, keyData *tinkpb.KeyData, outputPrefixType tinkpb.OutputPrefixType, idRequirement uint32) *protoserialization.KeySerialization {
	t.Helper()
	ks, err := protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
	if err != nil {
		t.Fatalf("protoserialization.NewKeySerialization(%v, %v, %v) err = %v, want nil", keyData, outputPrefixType, idRequirement, err)
	}
	return ks
}

func mustCreateKey(t *testing.T, keyValue []byte, variant xaesgcm.Variant, saltSize int, idRequirement uint32) *xaesgcm.Key {
	t.Helper()
	params, err := xaesgcm.NewParameters(variant, saltSize)
	if err != nil {
		t.Fatalf("xaesgcm.NewParameters(%v, %v) err = %v, want nil", variant, saltSize, err)
	}
	keyMaterial := secretdata.NewBytesFromData(keyValue, insecuresecretdataaccess.Token{})
	key, err := xaesgcm.NewKey(keyMaterial, idRequirement, params)
	if err != nil {
		t.Fatalf("xaesgcm.NewKey(keyMaterial, %v, params) err = %v, want nil", idRequirement, err)
	}
	return key
}

func TestParseKey(t *testing.T) {
	for _, tc := range []struct {
		name             string
		keySerialization *protoserialization.KeySerialization
		wantKey          *xaesgcm.Key
	}{
		{
			name: "TINK output prefix type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.XAesGcmKey",
				Value: mustMarshalProto(t, &xaesgcmpb.XAesGcmKey{
					KeyValue: []byte("12345678901234561234567890123456"),
					Params: &xaesgcmpb.XAesGcmParams{
						SaltSize: 12,
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 0x11223344),
			wantKey: mustCreateKey(t, []byte("12345678901234561234567890123456"), xaesgcm.VariantTink, 12, 0x11223344),
		},
		{
			name: "RAW output prefix type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.XAesGcmKey",
				Value: mustMarshalProto(t, &xaesgcmpb.XAesGcmKey{
					KeyValue: []byte("12345678901234561234567890123456"),
					Params: &xaesgcmpb.XAesGcmParams{
						SaltSize: 12,
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
			wantKey: mustCreateKey(t, []byte("12345678901234561234567890123456"), xaesgcm.VariantNoPrefix, 12, 0),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotKey, err := protoserialization.ParseKey(tc.keySerialization)
			if err != nil {
				t.Fatalf("protoserialization.ParseKey(%v) err = %v, want nil", tc.keySerialization, err)
			}
			if diff := cmp.Diff(gotKey, tc.wantKey); diff != "" {
				t.Errorf("protoserialization.ParseKey(%v) returned unexpected diff (-want +got):\n%s", tc.keySerialization, diff)
			}
		})
	}
}

func TestSerializeKey(t *testing.T) {
	keyValue := []byte("12345678901234561234567890123456")
	for _, tc := range []struct {
		name                 string
		key                  *xaesgcm.Key
		wantKeySerialization *protoserialization.KeySerialization
	}{
		{
			name: "key with TINK output prefix type",
			key:  mustCreateKey(t, keyValue, xaesgcm.VariantTink, 12, 0x11223344),
			wantKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.XAesGcmKey",
				Value: mustMarshalProto(t, &xaesgcmpb.XAesGcmKey{
					KeyValue: keyValue,
					Params: &xaesgcmpb.XAesGcmParams{
						SaltSize: 12,
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 0x11223344),
		},
		{
			name: "key with RAW output prefix type",
			key:  mustCreateKey(t, keyValue, xaesgcm.VariantNoPrefix, 12, 0x00),
			wantKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.XAesGcmKey",
				Value: mustMarshalProto(t, &xaesgcmpb.XAesGcmKey{
					KeyValue: keyValue,
					Params: &xaesgcmpb.XAesGcmParams{
						SaltSize: 12,
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.SerializeKey(tc.key)
			if err != nil {
				t.Fatalf("protoserialization.SerializeKey(&testKey{}) err = %v, want nil", err)
			}
			if diff := cmp.Diff(got, tc.wantKeySerialization); diff != "" {
				t.Errorf("protoserialization.SerializeKey(%v) returned unexpected diff (-want +got):\n%s", tc.key, diff)
			}
		})
	}
}

func mustCreateKeyTemplate(t *testing.T, outputPrefixType tinkpb.OutputPrefixType, saltSize uint32) *tinkpb.KeyTemplate {
	t.Helper()
	format := &xaesgcmpb.XAesGcmKeyFormat{
		Params: &xaesgcmpb.XAesGcmParams{
			SaltSize: saltSize,
		},
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          "type.googleapis.com/google.crypto.tink.XAesGcmKey",
		OutputPrefixType: outputPrefixType,
		Value:            mustMarshalProto(t, format),
	}
}

func mustCreateParameters(t *testing.T, variant xaesgcm.Variant, saltSize int) *xaesgcm.Parameters {
	t.Helper()
	params, err := xaesgcm.NewParameters(variant, saltSize)
	if err != nil {
		t.Fatalf("xaesgcm.NewParameters(%v, %v) err = %v, want nil", variant, saltSize, err)
	}
	return params
}

func TestSerializeParameters(t *testing.T) {
	for _, tc := range []struct {
		name            string
		parameters      key.Parameters
		wantKeyTemplate *tinkpb.KeyTemplate
	}{
		{
			name:            "TINK output prefix type",
			parameters:      mustCreateParameters(t, xaesgcm.VariantTink, 12),
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_TINK, 12),
		},
		{
			name:            "RAW output prefix type",
			parameters:      mustCreateParameters(t, xaesgcm.VariantNoPrefix, 12),
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_RAW, 12),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotKeyTemplate, err := protoserialization.SerializeParameters(tc.parameters)
			if err != nil {
				t.Fatalf("protoserialization.SerializeParameters(%v) err = %v, want nil", tc.parameters, err)
			}
			if diff := cmp.Diff(tc.wantKeyTemplate, gotKeyTemplate, protocmp.Transform()); diff != "" {
				t.Errorf("protoserialization.SerializeParameters(%v) returned unexpected diff (-want +got):\n%s", tc.parameters, diff)
			}
		})
	}
}
