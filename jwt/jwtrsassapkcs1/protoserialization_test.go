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

package jwtrsassapkcs1_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtrsassapkcs1"

	jwtrsapb "github.com/tink-crypto/tink-go/v2/proto/jwt_rsa_ssa_pkcs1_go_proto"
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

func mustCreateParameters(t *testing.T, kid jwtrsassapkcs1.KIDStrategy, alg jwtrsassapkcs1.Algorithm, modulusSize int) *jwtrsassapkcs1.Parameters {
	t.Helper()
	p, err := jwtrsassapkcs1.NewParameters(jwtrsassapkcs1.ParametersOpts{
		KidStrategy:       kid,
		Algorithm:         alg,
		ModulusSizeInBits: modulusSize,
		PublicExponent:    f4,
	})
	if err != nil {
		t.Fatalf("jwtrsassapkcs1.NewParameters() err = %v, want nil", err)
	}
	return p
}

func TestParametersSerializer(t *testing.T) {
	for _, tc := range []struct {
		params *jwtrsassapkcs1.Parameters
		wantKt *tinkpb.KeyTemplate
	}{
		{
			params: mustCreateParameters(t, jwtrsassapkcs1.Base64EncodedKeyIDAsKID, jwtrsassapkcs1.RS256, 2048),
			wantKt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1KeyFormat{
					Algorithm:         jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256,
					ModulusSizeInBits: 2048,
					PublicExponent:    []byte{0x01, 0x00, 0x01},
					Version:           0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			params: mustCreateParameters(t, jwtrsassapkcs1.Base64EncodedKeyIDAsKID, jwtrsassapkcs1.RS384, 3072),
			wantKt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1KeyFormat{
					Algorithm:         jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS384,
					ModulusSizeInBits: 3072,
					PublicExponent:    []byte{0x01, 0x00, 0x01},
					Version:           0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			params: mustCreateParameters(t, jwtrsassapkcs1.Base64EncodedKeyIDAsKID, jwtrsassapkcs1.RS512, 4096),
			wantKt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1KeyFormat{
					Algorithm:         jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS512,
					ModulusSizeInBits: 4096,
					PublicExponent:    []byte{0x01, 0x00, 0x01},
					Version:           0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			params: mustCreateParameters(t, jwtrsassapkcs1.IgnoredKID, jwtrsassapkcs1.RS256, 2048),
			wantKt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1KeyFormat{
					Algorithm:         jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256,
					ModulusSizeInBits: 2048,
					PublicExponent:    []byte{0x01, 0x00, 0x01},
					Version:           0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			params: mustCreateParameters(t, jwtrsassapkcs1.CustomKID, jwtrsassapkcs1.RS256, 2048),
			wantKt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1KeyFormat{
					Algorithm:         jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256,
					ModulusSizeInBits: 2048,
					PublicExponent:    []byte{0x01, 0x00, 0x01},
					Version:           0,
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
				t.Errorf("protoserialization.SerializeParameters(%v) returned unexpected diff (-want +got): \n%s", tc.params, diff)
			}
		})
	}
}

func TestParametersParser(t *testing.T) {
	for _, tc := range []struct {
		wantParams *jwtrsassapkcs1.Parameters
		kt         *tinkpb.KeyTemplate
	}{
		{
			wantParams: mustCreateParameters(t, jwtrsassapkcs1.Base64EncodedKeyIDAsKID, jwtrsassapkcs1.RS256, 2048),
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1KeyFormat{
					Algorithm:         jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256,
					ModulusSizeInBits: 2048,
					PublicExponent:    []byte{0x01, 0x00, 0x01},
					Version:           0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			wantParams: mustCreateParameters(t, jwtrsassapkcs1.Base64EncodedKeyIDAsKID, jwtrsassapkcs1.RS384, 3072),
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1KeyFormat{
					Algorithm:         jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS384,
					ModulusSizeInBits: 3072,
					PublicExponent:    []byte{0x01, 0x00, 0x01},
					Version:           0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			wantParams: mustCreateParameters(t, jwtrsassapkcs1.Base64EncodedKeyIDAsKID, jwtrsassapkcs1.RS512, 4096),
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1KeyFormat{
					Algorithm:         jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS512,
					ModulusSizeInBits: 4096,
					PublicExponent:    []byte{0x01, 0x00, 0x01},
					Version:           0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			wantParams: mustCreateParameters(t, jwtrsassapkcs1.IgnoredKID, jwtrsassapkcs1.RS256, 2048),
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1KeyFormat{
					Algorithm:         jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256,
					ModulusSizeInBits: 2048,
					PublicExponent:    []byte{0x01, 0x00, 0x01},
					Version:           0,
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
				t.Errorf("protoserialization.ParseParameters(%v) returned unexpected diff (-want +got): \n%s", tc.kt, diff)
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
			name: "invalid key format proto",
			kt: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value:            []byte("invalid proto"),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "nil value",
			kt: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value:            nil,
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "unknown output prefix type",
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1KeyFormat{
					Algorithm:         jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256,
					ModulusSizeInBits: 2048,
					PublicExponent:    []byte{0x01, 0x00, 0x01},
					Version:           0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_UNKNOWN_PREFIX,
			},
		},
		{
			name: "invalid output prefix type",
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1KeyFormat{
					Algorithm:         jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256,
					ModulusSizeInBits: 2048,
					PublicExponent:    []byte{0x01, 0x00, 0x01},
					Version:           0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_CRUNCHY,
			},
		},
		{
			name: "invalid version",
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1KeyFormat{
					Algorithm:         jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256,
					ModulusSizeInBits: 2048,
					PublicExponent:    []byte{0x01, 0x00, 0x01},
					Version:           1,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			name: "invalid algorithm",
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1KeyFormat{
					Algorithm:         jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS_UNKNOWN,
					ModulusSizeInBits: 2048,
					PublicExponent:    []byte{0x01, 0x00, 0x01},
					Version:           0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "invalid modulus size",
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1KeyFormat{
					Algorithm:         jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256,
					ModulusSizeInBits: 2047,
					PublicExponent:    []byte{0x01, 0x00, 0x01},
					Version:           0,
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
