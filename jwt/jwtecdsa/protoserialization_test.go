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

package jwtecdsa_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtecdsa"

	jwtecdsapb "github.com/tink-crypto/tink-go/v2/proto/jwt_ecdsa_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func mustSerializeKeyFormat(t *testing.T, keyFormat *jwtecdsapb.JwtEcdsaKeyFormat) []byte {
	serializedKeyFormat, err := proto.Marshal(keyFormat)
	if err != nil {
		t.Fatalf("failed to marshal JwtEcdsaKeyFormat: %v", err)
	}
	return serializedKeyFormat
}

func TestParametersSerializer(t *testing.T) {
	for _, tc := range []struct {
		params *jwtecdsa.Parameters
		wantKt *tinkpb.KeyTemplate
	}{
		{
			params: mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES256),
			wantKt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value: mustSerializeKeyFormat(t, &jwtecdsapb.JwtEcdsaKeyFormat{
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES256,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			params: mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES384),
			wantKt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value: mustSerializeKeyFormat(t, &jwtecdsapb.JwtEcdsaKeyFormat{
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES384,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			params: mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES512),
			wantKt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value: mustSerializeKeyFormat(t, &jwtecdsapb.JwtEcdsaKeyFormat{
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES512,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			params: mustCreateParameters(t, jwtecdsa.IgnoredKID, jwtecdsa.ES256),
			wantKt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value: mustSerializeKeyFormat(t, &jwtecdsapb.JwtEcdsaKeyFormat{
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES256,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			params: mustCreateParameters(t, jwtecdsa.IgnoredKID, jwtecdsa.ES384),
			wantKt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value: mustSerializeKeyFormat(t, &jwtecdsapb.JwtEcdsaKeyFormat{
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES384,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			params: mustCreateParameters(t, jwtecdsa.IgnoredKID, jwtecdsa.ES512),
			wantKt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value: mustSerializeKeyFormat(t, &jwtecdsapb.JwtEcdsaKeyFormat{
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES512,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			params: mustCreateParameters(t, jwtecdsa.CustomKID, jwtecdsa.ES256),
			wantKt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value: mustSerializeKeyFormat(t, &jwtecdsapb.JwtEcdsaKeyFormat{
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES256,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			params: mustCreateParameters(t, jwtecdsa.CustomKID, jwtecdsa.ES384),
			wantKt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value: mustSerializeKeyFormat(t, &jwtecdsapb.JwtEcdsaKeyFormat{
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES384,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			params: mustCreateParameters(t, jwtecdsa.CustomKID, jwtecdsa.ES512),
			wantKt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value: mustSerializeKeyFormat(t, &jwtecdsapb.JwtEcdsaKeyFormat{
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES512,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
	} {
		t.Run(fmt.Sprintf("%v_%v", tc.params.KIDStrategy(), tc.params.Algorithm()), func(t *testing.T) {
			got, err := protoserialization.SerializeParameters(tc.params)
			if err != nil {
				t.Fatalf("protoserialization.SerializeParameters(%v) err = %v, want nil", tc.params, err)
			}
			if diff := cmp.Diff(tc.wantKt, got, protocmp.Transform()); diff != "" {
				t.Errorf("protoserialization.SerializeParameters(%v) returned unexpected diff (-want +got):\n%s", tc.params, diff)
			}
		})
	}
}

func TestParametersParser(t *testing.T) {
	for _, tc := range []struct {
		wantParams *jwtecdsa.Parameters
		kt         *tinkpb.KeyTemplate
	}{
		{
			wantParams: mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES256),
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value: mustSerializeKeyFormat(t, &jwtecdsapb.JwtEcdsaKeyFormat{
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES256,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			wantParams: mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES384),
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value: mustSerializeKeyFormat(t, &jwtecdsapb.JwtEcdsaKeyFormat{
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES384,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			wantParams: mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES512),
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value: mustSerializeKeyFormat(t, &jwtecdsapb.JwtEcdsaKeyFormat{
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES512,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			wantParams: mustCreateParameters(t, jwtecdsa.IgnoredKID, jwtecdsa.ES256),
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value: mustSerializeKeyFormat(t, &jwtecdsapb.JwtEcdsaKeyFormat{
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES256,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			wantParams: mustCreateParameters(t, jwtecdsa.IgnoredKID, jwtecdsa.ES384),
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value: mustSerializeKeyFormat(t, &jwtecdsapb.JwtEcdsaKeyFormat{
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES384,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			wantParams: mustCreateParameters(t, jwtecdsa.IgnoredKID, jwtecdsa.ES512),
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value: mustSerializeKeyFormat(t, &jwtecdsapb.JwtEcdsaKeyFormat{
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES512,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
	} {
		t.Run(fmt.Sprintf("%v_%v", tc.wantParams.Algorithm(), tc.kt.GetOutputPrefixType()), func(t *testing.T) {
			got, err := protoserialization.ParseParameters(tc.kt)
			if err != nil {
				t.Fatalf("protoserialization.ParseParameters(%v) err = %v, want nil", tc.kt, err)
			}
			if diff := cmp.Diff(tc.wantParams, got); diff != "" {
				t.Errorf("protoserialization.ParseParameters(%v) returned unexpected diff (-want +got):\n%s", tc.kt, diff)
			}
		})
	}
}

func TestParametersParser_Errors(t *testing.T) {
	for _, tc := range []struct {
		name string
		kt   *tinkpb.KeyTemplate
	}{
		{
			name: "nil value",
			kt: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value:            nil,
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "unknown output prefix type",
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value: mustSerializeKeyFormat(t, &jwtecdsapb.JwtEcdsaKeyFormat{
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES384,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_UNKNOWN_PREFIX,
			},
		},
		{
			name: "invalid output prefix type",
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value: mustSerializeKeyFormat(t, &jwtecdsapb.JwtEcdsaKeyFormat{
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES384,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_CRUNCHY,
			},
		},
		{
			name: "invalid version",
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value: mustSerializeKeyFormat(t, &jwtecdsapb.JwtEcdsaKeyFormat{
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES384,
					Version:   1,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "invalid algorithm",
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value: mustSerializeKeyFormat(t, &jwtecdsapb.JwtEcdsaKeyFormat{
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES_UNKNOWN,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.ParseParameters(tc.kt); err == nil {
				t.Errorf("protoserialization.ParseParameters(%v) error = nil, want error", tc.kt)
			}
		})
	}
}
