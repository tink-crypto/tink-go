// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/Lycense-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

package jwthmac_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/jwt/jwthmac"
	"github.com/tink-crypto/tink-go/v2/secretdata"

	jwthmacpb "github.com/tink-crypto/tink-go/v2/proto/jwt_hmac_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func mustMarshal(t *testing.T, msg proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	return b
}

type parametersTestCase struct {
	name        string
	params      *jwthmac.Parameters
	keyTemplate *tinkpb.KeyTemplate
}

func getParametersTestCases(t *testing.T) []*parametersTestCase {
	return []*parametersTestCase{
		{
			name:   "HS256 with TINK prefix",
			params: mustCreateParameters(t, 32, jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS256),
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtHmacKey",
				Value: mustMarshal(t, &jwthmacpb.JwtHmacKeyFormat{
					Algorithm: jwthmacpb.JwtHmacAlgorithm_HS256,
					KeySize:   32,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name:   "HS384 with TINK prefix",
			params: mustCreateParameters(t, 48, jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS384),
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtHmacKey",
				Value: mustMarshal(t, &jwthmacpb.JwtHmacKeyFormat{
					Algorithm: jwthmacpb.JwtHmacAlgorithm_HS384,
					KeySize:   48,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name:   "HS512 with TINK prefix",
			params: mustCreateParameters(t, 64, jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS512),
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtHmacKey",
				Value: mustMarshal(t, &jwthmacpb.JwtHmacKeyFormat{
					Algorithm: jwthmacpb.JwtHmacAlgorithm_HS512,
					KeySize:   64,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name:   "HS256 with RAW prefix (Ignored KID)",
			params: mustCreateParameters(t, 32, jwthmac.IgnoredKID, jwthmac.HS256),
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtHmacKey",
				Value: mustMarshal(t, &jwthmacpb.JwtHmacKeyFormat{
					Algorithm: jwthmacpb.JwtHmacAlgorithm_HS256,
					KeySize:   32,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			name:   "HS256 with RAW prefix (Custom KID)",
			params: mustCreateParameters(t, 32, jwthmac.CustomKID, jwthmac.HS256),
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtHmacKey",
				Value: mustMarshal(t, &jwthmacpb.JwtHmacKeyFormat{
					Algorithm: jwthmacpb.JwtHmacAlgorithm_HS256,
					KeySize:   32,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
	}
}

func TestParametersSerializer(t *testing.T) {
	for _, tc := range getParametersTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.SerializeParameters(tc.params)
			if err != nil {
				t.Fatalf("protoserialization.SerializeParameters(%v) err = %v, want nil", tc.params, err)
			}
			if diff := cmp.Diff(tc.keyTemplate, got, protocmp.Transform()); diff != "" {
				t.Errorf("protoserialization.SerializeParameters(%v) returned unexpected diff (-want +got):\n%s", tc.params, diff)
			}
		})
	}
}

func TestParametersParser(t *testing.T) {
	var testCasesToParse []*parametersTestCase
	for _, tc := range getParametersTestCases(t) {
		if tc.params.KIDStrategy() != jwthmac.CustomKID {
			testCasesToParse = append(testCasesToParse, tc)
		}
	}
	for _, tc := range testCasesToParse {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.ParseParameters(tc.keyTemplate)
			if err != nil {
				t.Fatalf("protoserialization.ParseParameters(%v) err = %v, want nil", tc.keyTemplate, err)
			}
			if diff := cmp.Diff(tc.params, got); diff != "" {
				t.Errorf("protoserialization.ParseParameters(%v) returned unexpected diff (-want +got):\n%s", tc.keyTemplate, diff)
			}
		})
	}
}

func TestParametersParser_Errors(t *testing.T) {
	for _, tc := range []struct {
		name        string
		keyTemplate *tinkpb.KeyTemplate
	}{
		{
			name: "nil value",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.JwtHmacKey",
				Value:            nil,
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "unknown output prefix type",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtHmacKey",
				Value: mustMarshal(t, &jwthmacpb.JwtHmacKeyFormat{
					Algorithm: jwthmacpb.JwtHmacAlgorithm_HS256,
					KeySize:   32,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_UNKNOWN_PREFIX,
			},
		},
		{
			name: "invalid output prefix type",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtHmacKey",
				Value: mustMarshal(t, &jwthmacpb.JwtHmacKeyFormat{
					Algorithm: jwthmacpb.JwtHmacAlgorithm_HS256,
					KeySize:   32,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_LEGACY,
			},
		},
		{
			name: "invalid version",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtHmacKey",
				Value: mustMarshal(t, &jwthmacpb.JwtHmacKeyFormat{
					Algorithm: jwthmacpb.JwtHmacAlgorithm_HS256,
					KeySize:   32,
					Version:   1,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "invalid algorithm",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtHmacKey",
				Value: mustMarshal(t, &jwthmacpb.JwtHmacKeyFormat{
					Algorithm: jwthmacpb.JwtHmacAlgorithm_HS_UNKNOWN,
					KeySize:   32,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "invalid key size",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtHmacKey",
				Value: mustMarshal(t, &jwthmacpb.JwtHmacKeyFormat{
					Algorithm: jwthmacpb.JwtHmacAlgorithm_HS256,
					KeySize:   15,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.ParseParameters(tc.keyTemplate); err == nil {
				t.Errorf("protoserialization.ParseParameters(%v) error = nil, want error", tc.keyTemplate)
			}
		})
	}
}

func mustNewKeySerialization(t *testing.T, keyData *tinkpb.KeyData, outputPrefixType tinkpb.OutputPrefixType, idRequirement uint32) *protoserialization.KeySerialization {
	t.Helper()
	keySerialization, err := protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
	if err != nil {
		t.Fatalf("protoserialization.NewKeySerialization() err = %v, want nil", err)
	}
	return keySerialization
}

func mustCreateKey(t *testing.T, opts jwthmac.KeyOpts) *jwthmac.Key {
	t.Helper()
	key, err := jwthmac.NewKey(opts)
	if err != nil {
		t.Fatalf("jwthmac.NewKey() err = %v, want nil", err)
	}
	return key
}

type keySerializationTestCase struct {
	name             string
	key              *jwthmac.Key
	keySerialization *protoserialization.KeySerialization
}

func getKeySerializationTestCases(t *testing.T) []*keySerializationTestCase {
	keyBytes32 := secretdata.NewBytesFromData([]byte("01234567890123456789012345678901"), insecuresecretdataaccess.Token{})
	keyBytes48 := secretdata.NewBytesFromData([]byte("012345678901234567890123456789012345678901234567"), insecuresecretdataaccess.Token{})
	keyBytes64 := secretdata.NewBytesFromData([]byte("0123456789012345678901234567890123456789012345678901234567890123"), insecuresecretdataaccess.Token{})

	return []*keySerializationTestCase{
		{
			name: "HS256_TINK",
			key: mustCreateKey(t, jwthmac.KeyOpts{
				Parameters:    mustCreateParameters(t, 32, jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS256),
				KeyBytes:      keyBytes32,
				IDRequirement: 123,
			}),
			keySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.JwtHmacKey",
				Value:           mustMarshal(t, &jwthmacpb.JwtHmacKey{Version: 0, Algorithm: jwthmacpb.JwtHmacAlgorithm_HS256, KeyValue: keyBytes32.Data(insecuresecretdataaccess.Token{})}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 123),
		},
		{
			name: "HS384_TINK",
			key: mustCreateKey(t, jwthmac.KeyOpts{
				Parameters:    mustCreateParameters(t, 48, jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS384),
				KeyBytes:      keyBytes48,
				IDRequirement: 456,
			}),
			keySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.JwtHmacKey",
				Value:           mustMarshal(t, &jwthmacpb.JwtHmacKey{Version: 0, Algorithm: jwthmacpb.JwtHmacAlgorithm_HS384, KeyValue: keyBytes48.Data(insecuresecretdataaccess.Token{})}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 456),
		},
		{
			name: "HS512_TINK",
			key: mustCreateKey(t, jwthmac.KeyOpts{
				Parameters:    mustCreateParameters(t, 64, jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS512),
				KeyBytes:      keyBytes64,
				IDRequirement: 789,
			}),
			keySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.JwtHmacKey",
				Value:           mustMarshal(t, &jwthmacpb.JwtHmacKey{Version: 0, Algorithm: jwthmacpb.JwtHmacAlgorithm_HS512, KeyValue: keyBytes64.Data(insecuresecretdataaccess.Token{})}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 789),
		},
		{
			name: "HS256_RAW_Ignored",
			key: mustCreateKey(t, jwthmac.KeyOpts{
				Parameters: mustCreateParameters(t, 32, jwthmac.IgnoredKID, jwthmac.HS256),
				KeyBytes:   keyBytes32,
			}),
			keySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.JwtHmacKey",
				Value:           mustMarshal(t, &jwthmacpb.JwtHmacKey{Version: 0, Algorithm: jwthmacpb.JwtHmacAlgorithm_HS256, KeyValue: keyBytes32.Data(insecuresecretdataaccess.Token{})}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "HS256_RAW_Custom",
			key: mustCreateKey(t, jwthmac.KeyOpts{
				Parameters:   mustCreateParameters(t, 32, jwthmac.CustomKID, jwthmac.HS256),
				KeyBytes:     keyBytes32,
				CustomKID:    "custom",
				HasCustomKID: true,
			}),
			keySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtHmacKey",
				Value: mustMarshal(t, &jwthmacpb.JwtHmacKey{
					Version:   0,
					Algorithm: jwthmacpb.JwtHmacAlgorithm_HS256,
					KeyValue:  keyBytes32.Data(insecuresecretdataaccess.Token{}),
					CustomKid: &jwthmacpb.JwtHmacKey_CustomKid{Value: "custom"},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
	}
}

func TestKeySerializer(t *testing.T) {
	for _, tc := range getKeySerializationTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			keySerialization, err := protoserialization.SerializeKey(tc.key)
			if err != nil {
				t.Fatalf("protoserialization.SerializeKey() err = %v, want nil", err)
			}
			if diff := cmp.Diff(tc.keySerialization, keySerialization, protocmp.Transform(), cmp.AllowUnexported(protoserialization.KeySerialization{})); diff != "" {
				t.Errorf("unexpected diff (-want +got): %s", diff)
			}
		})
	}
}

func TestKeyParser(t *testing.T) {
	for _, tc := range getKeySerializationTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.ParseKey(tc.keySerialization)
			if err != nil {
				t.Fatalf("protoserialization.ParseKey() err = %v, want nil", err)
			}
			if diff := cmp.Diff(tc.key, got, protocmp.Transform(), cmp.AllowUnexported(protoserialization.KeySerialization{})); diff != "" {
				t.Errorf("unexpected diff (-want +got): %s", diff)
			}
		})
	}
}
