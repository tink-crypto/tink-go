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
	"math/big"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtrsassapkcs1"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testutil/testonlyinsecuresecretdataaccess"

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

func mustNewKeySerialization(t *testing.T, keyData *tinkpb.KeyData, outputPrefixType tinkpb.OutputPrefixType, idRequirement uint32) *protoserialization.KeySerialization {
	t.Helper()
	keySerialization, err := protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
	if err != nil {
		t.Fatalf("protoserialization.NewKeySerialization() err = %v, want nil", err)
	}
	return keySerialization
}

func mustCreatePublicKey(t *testing.T, opts jwtrsassapkcs1.PublicKeyOpts) *jwtrsassapkcs1.PublicKey {
	t.Helper()
	key, err := jwtrsassapkcs1.NewPublicKey(opts)
	if err != nil {
		t.Fatalf("jwtrsassapkcs1.NewPublicKey() err = %v, want nil", err)
	}
	return key
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
		{
			name: "invalid public exponent",
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1KeyFormat{
					Algorithm:         jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256,
					ModulusSizeInBits: 2048,
					PublicExponent:    []byte{0x01, 0x00},
					Version:           0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "invalid public exponent too large to fit in int64",
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1KeyFormat{
					Algorithm:         jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256,
					ModulusSizeInBits: 2048,
					PublicExponent:    new(big.Int).Lsh(big.NewInt(1), 64).Bytes(), // 2^64
					Version:           0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.ParseParameters(tc.kt); err == nil {
				t.Errorf("protoserialization.ParseParameters(%v) error = nil, want error", tc.kt)
			} else {
				t.Logf("protoserialization.ParseParameters(%v) error = %v", tc.kt, err)
			}
		})
	}
}

type protoserializationPublicKeyTestCase struct {
	name                   string
	publicKey              *jwtrsassapkcs1.PublicKey
	publicKeySerialization *protoserialization.KeySerialization
}

func TestPublicKeySerializer(t *testing.T) {
	e := []byte{0x01, 0x00, 0x01}
	testCases := []*protoserializationPublicKeyTestCase{
		{
			name: fmt.Sprintf("%v_%v_TINK", jwtrsassapkcs1.Base64EncodedKeyIDAsKID, jwtrsassapkcs1.RS256),
			publicKey: mustCreatePublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
				Modulus:       mustBase64Decode(t, n2048Base64),
				IDRequirement: 0x01020304,
				HasCustomKID:  false,
				Parameters:    mustCreateParameters(t, jwtrsassapkcs1.Base64EncodedKeyIDAsKID, jwtrsassapkcs1.RS256, 2048),
			}),
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1PublicKey{
					Version:   0,
					Algorithm: jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256,
					N:         mustBase64Decode(t, n2048Base64),
					E:         e,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 0x01020304),
		},
		{
			name: fmt.Sprintf("%v_%v_RAW", jwtrsassapkcs1.IgnoredKID, jwtrsassapkcs1.RS384),
			publicKey: mustCreatePublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
				Modulus:      mustBase64Decode(t, n3072Base64),
				HasCustomKID: false,
				Parameters:   mustCreateParameters(t, jwtrsassapkcs1.IgnoredKID, jwtrsassapkcs1.RS384, 3072),
			}),
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1PublicKey{
					Version:   0,
					Algorithm: jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS384,
					N:         mustBase64Decode(t, n3072Base64),
					E:         e,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: fmt.Sprintf("%v_%v_RAW", jwtrsassapkcs1.CustomKID, jwtrsassapkcs1.RS512),
			publicKey: mustCreatePublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
				Modulus:      mustBase64Decode(t, n4096Base64),
				HasCustomKID: true,
				CustomKID:    "customKID123",
				Parameters:   mustCreateParameters(t, jwtrsassapkcs1.CustomKID, jwtrsassapkcs1.RS512, 4096),
			}),
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1PublicKey{
					Version:   0,
					Algorithm: jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS512,
					N:         mustBase64Decode(t, n4096Base64),
					E:         e,
					CustomKid: &jwtrsapb.JwtRsaSsaPkcs1PublicKey_CustomKid{Value: "customKID123"},
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keySerialization, err := protoserialization.SerializeKey(tc.publicKey)
			if err != nil {
				t.Fatalf("protoserialization.SerializeKey() err = %v, want nil", err)
			}
			if diff := cmp.Diff(tc.publicKeySerialization, keySerialization, protocmp.Transform(), cmp.AllowUnexported(protoserialization.KeySerialization{})); diff != "" {
				t.Errorf("unexpected diff (-want +got): %s", diff)
			}
		})
	}
}

func TestPublicKeyParser(t *testing.T) {
	e := []byte{0x01, 0x00, 0x01}
	testCases := []*protoserializationPublicKeyTestCase{
		{
			name: fmt.Sprintf("%v_%v_TINK", jwtrsassapkcs1.Base64EncodedKeyIDAsKID, jwtrsassapkcs1.RS256),
			publicKey: mustCreatePublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
				Modulus:       mustBase64Decode(t, n2048Base64),
				IDRequirement: 0x01020304,
				HasCustomKID:  false,
				Parameters:    mustCreateParameters(t, jwtrsassapkcs1.Base64EncodedKeyIDAsKID, jwtrsassapkcs1.RS256, 2048),
			}),
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1PublicKey{
					Version:   0,
					Algorithm: jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256,
					N:         mustBase64Decode(t, n2048Base64),
					E:         e,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 0x01020304),
		},
		{
			name: fmt.Sprintf("%v_%v_RAW", jwtrsassapkcs1.IgnoredKID, jwtrsassapkcs1.RS384),
			publicKey: mustCreatePublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
				Modulus:      mustBase64Decode(t, n3072Base64),
				HasCustomKID: false,
				Parameters:   mustCreateParameters(t, jwtrsassapkcs1.IgnoredKID, jwtrsassapkcs1.RS384, 3072),
			}),
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1PublicKey{
					Version:   0,
					Algorithm: jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS384,
					N:         mustBase64Decode(t, n3072Base64),
					E:         e,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: fmt.Sprintf("%v_%v_RAW", jwtrsassapkcs1.CustomKID, jwtrsassapkcs1.RS512),
			publicKey: mustCreatePublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
				Modulus:      mustBase64Decode(t, n4096Base64),
				HasCustomKID: true,
				CustomKID:    "customKID123",
				Parameters:   mustCreateParameters(t, jwtrsassapkcs1.CustomKID, jwtrsassapkcs1.RS512, 4096),
			}),
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1PublicKey{
					Version:   0,
					Algorithm: jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS512,
					N:         mustBase64Decode(t, n4096Base64),
					E:         e,
					CustomKid: &jwtrsapb.JwtRsaSsaPkcs1PublicKey_CustomKid{Value: "customKID123"},
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.ParseKey(tc.publicKeySerialization)
			if err != nil {
				t.Fatalf("protoserialization.ParseKey() err = %v, want nil", err)
			}
			if diff := cmp.Diff(tc.publicKey, got, protocmp.Transform(), cmp.AllowUnexported(protoserialization.KeySerialization{})); diff != "" {
				t.Errorf("unexpected diff (-want +got): %s", diff)
			}
		})
	}
}

func TestPublicKeyParser_Errors(t *testing.T) {
	e := new(big.Int).SetInt64(f4).Bytes()
	for _, tc := range []struct {
		name                   string
		publicKeySerialization *protoserialization.KeySerialization
	}{
		{
			name: "invalid_key_material_type",
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1PublicKey{
					Version:   0,
					Algorithm: jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256,
					N:         mustBase64Decode(t, n2048Base64),
					E:         e,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "modulus_too_small",
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1PublicKey{
					Version:   0,
					Algorithm: jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256,
					N:         mustBase64Decode(t, n2048Base64)[1:],
					E:         e,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "invalid_exponent_even",
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1PublicKey{
					Version:   0,
					Algorithm: jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256,
					N:         mustBase64Decode(t, n2048Base64),
					E:         new(big.Int).SetInt64(f4 + 1).Bytes(),
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "exponent_too_small",
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1PublicKey{
					Version:   0,
					Algorithm: jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256,
					N:         mustBase64Decode(t, n2048Base64),
					E:         new(big.Int).SetInt64(f4 - 2).Bytes(),
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "exponent_too_large",
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1PublicKey{
					Version:   0,
					Algorithm: jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256,
					N:         mustBase64Decode(t, n2048Base64),
					E:         new(big.Int).Lsh(big.NewInt(1), 31).Bytes(),
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "invalid_version",
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1PublicKey{
					Version:   1,
					Algorithm: jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256,
					N:         mustBase64Decode(t, n2048Base64),
					E:         e,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "unknown_algorithm",
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1PublicKey{
					Version:   0,
					Algorithm: jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS_UNKNOWN,
					N:         mustBase64Decode(t, n2048Base64),
					E:         e,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "tink_with_custom_kid",
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1PublicKey{
					Version:   0,
					Algorithm: jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256,
					N:         mustBase64Decode(t, n2048Base64),
					E:         e,
					CustomKid: &jwtrsapb.JwtRsaSsaPkcs1PublicKey_CustomKid{Value: "myCustomKID"},
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.ParseKey(tc.publicKeySerialization); err == nil {
				t.Error("protoserialization.ParseKey() err = nil, want error")
			} else {
				t.Logf("protoserialization.ParseKey() err = %v", err)
			}
		})
	}
}

type protoserializationPrivateKeyTestCase struct {
	name                    string
	privateKey              *jwtrsassapkcs1.PrivateKey
	privateKeySerialization *protoserialization.KeySerialization
}

func protoserializationPrivateKeyTestCases(t *testing.T) []*protoserializationPrivateKeyTestCase {
	t.Helper()
	e := []byte{0x01, 0x00, 0x01}
	return []*protoserializationPrivateKeyTestCase{
		{
			name: "RS256_2048_TINK",
			privateKey: mustCreatePrivateKey(t, jwtrsassapkcs1.PrivateKeyOpts{
				PublicKey: mustCreatePublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Modulus:       mustBase64Decode(t, n2048Base64),
					IDRequirement: 0x01020304,
					Parameters:    mustCreateParameters(t, jwtrsassapkcs1.Base64EncodedKeyIDAsKID, jwtrsassapkcs1.RS256, 2048),
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), testonlyinsecuresecretdataaccess.Token()),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), testonlyinsecuresecretdataaccess.Token()),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), testonlyinsecuresecretdataaccess.Token()),
			}),
			privateKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1PrivateKey{
					Version: 0,
					PublicKey: &jwtrsapb.JwtRsaSsaPkcs1PublicKey{
						Version:   0,
						Algorithm: jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256,
						N:         mustBase64Decode(t, n2048Base64),
						E:         e,
					},
					D:   mustBase64Decode(t, d2048Base64),
					P:   mustBase64Decode(t, p2048Base64),
					Q:   mustBase64Decode(t, q2048Base64),
					Dp:  mustBase64Decode(t, dp2048Base64),
					Dq:  mustBase64Decode(t, dq2048Base64),
					Crt: mustBase64Decode(t, qInv2048Base64),
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 0x01020304),
		},
		{
			name: "RS384_3072_RAW_CustomKID",
			privateKey: mustCreatePrivateKey(t, jwtrsassapkcs1.PrivateKeyOpts{
				PublicKey: mustCreatePublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Modulus:      mustBase64Decode(t, n3072Base64),
					HasCustomKID: true,
					CustomKID:    "custom123",
					Parameters:   mustCreateParameters(t, jwtrsassapkcs1.CustomKID, jwtrsassapkcs1.RS384, 3072),
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d3072Base64), testonlyinsecuresecretdataaccess.Token()),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p3072Base64), testonlyinsecuresecretdataaccess.Token()),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q3072Base64), testonlyinsecuresecretdataaccess.Token()),
			}),
			privateKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1PrivateKey{
					Version: 0,
					PublicKey: &jwtrsapb.JwtRsaSsaPkcs1PublicKey{
						Version:   0,
						Algorithm: jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS384,
						N:         mustBase64Decode(t, n3072Base64),
						E:         e,
						CustomKid: &jwtrsapb.JwtRsaSsaPkcs1PublicKey_CustomKid{Value: "custom123"},
					},
					D:   mustBase64Decode(t, d3072Base64),
					P:   mustBase64Decode(t, p3072Base64),
					Q:   mustBase64Decode(t, q3072Base64),
					Dp:  mustBase64Decode(t, dp3072Base64),
					Dq:  mustBase64Decode(t, dq3072Base64),
					Crt: mustBase64Decode(t, qInv3072Base64),
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "RS512_4096_RAW_IgnoredKID",
			privateKey: mustCreatePrivateKey(t, jwtrsassapkcs1.PrivateKeyOpts{
				PublicKey: mustCreatePublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Modulus:      mustBase64Decode(t, n4096Base64),
					HasCustomKID: false,
					Parameters:   mustCreateParameters(t, jwtrsassapkcs1.IgnoredKID, jwtrsassapkcs1.RS512, 4096),
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d4096Base64), testonlyinsecuresecretdataaccess.Token()),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p4096Base64), testonlyinsecuresecretdataaccess.Token()),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q4096Base64), testonlyinsecuresecretdataaccess.Token()),
			}),
			privateKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1PrivateKey{
					Version: 0,
					PublicKey: &jwtrsapb.JwtRsaSsaPkcs1PublicKey{
						Version:   0,
						Algorithm: jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS512,
						N:         mustBase64Decode(t, n4096Base64),
						E:         e,
					},
					D:   mustBase64Decode(t, d4096Base64),
					P:   mustBase64Decode(t, p4096Base64),
					Q:   mustBase64Decode(t, q4096Base64),
					Dp:  mustBase64Decode(t, dp4096Base64),
					Dq:  mustBase64Decode(t, dq4096Base64),
					Crt: mustBase64Decode(t, qInv4096Base64),
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
	}
}

func TestPrivateKeySerializer(t *testing.T) {
	for _, tc := range protoserializationPrivateKeyTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			keySerialization, err := protoserialization.SerializeKey(tc.privateKey)
			if err != nil {
				t.Fatalf("protoserialization.SerializeKey() err = %v, want nil", err)
			}
			if diff := cmp.Diff(tc.privateKeySerialization, keySerialization, protocmp.Transform(), cmp.AllowUnexported(protoserialization.KeySerialization{})); diff != "" {
				t.Errorf("unexpected diff (-want +got): %s", diff)
			}
		})
	}
}

func TestPrivateKeyParser(t *testing.T) {
	for _, tc := range append(protoserializationPrivateKeyTestCases(t),
		&protoserializationPrivateKeyTestCase{
			name: "RS256_2048_TINK_trailing_zeros",
			privateKey: mustCreatePrivateKey(t, jwtrsassapkcs1.PrivateKeyOpts{
				PublicKey: mustCreatePublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Modulus:       mustBase64Decode(t, n2048Base64),
					IDRequirement: 0x01020304,
					Parameters:    mustCreateParameters(t, jwtrsassapkcs1.Base64EncodedKeyIDAsKID, jwtrsassapkcs1.RS256, 2048),
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), testonlyinsecuresecretdataaccess.Token()),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), testonlyinsecuresecretdataaccess.Token()),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), testonlyinsecuresecretdataaccess.Token()),
			}),
			privateKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1PrivateKey{
					Version: 0,
					PublicKey: &jwtrsapb.JwtRsaSsaPkcs1PublicKey{
						Version:   0,
						Algorithm: jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256,
						N:         mustBase64Decode(t, n2048Base64),
						E:         new(big.Int).SetInt64(f4).Bytes(),
					},
					D:   slices.Concat([]byte{0x00, 0x00, 0x00, 0x00}, mustBase64Decode(t, d2048Base64)),
					P:   slices.Concat([]byte{0x00, 0x00, 0x00, 0x00}, mustBase64Decode(t, p2048Base64)),
					Q:   slices.Concat([]byte{0x00, 0x00, 0x00, 0x00}, mustBase64Decode(t, q2048Base64)),
					Dp:  slices.Concat([]byte{0x00, 0x00, 0x00, 0x00}, mustBase64Decode(t, dp2048Base64)),
					Dq:  slices.Concat([]byte{0x00, 0x00, 0x00, 0x00}, mustBase64Decode(t, dq2048Base64)),
					Crt: slices.Concat([]byte{0x00, 0x00, 0x00, 0x00}, mustBase64Decode(t, qInv2048Base64)),
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 0x01020304),
		},
	) {
		t.Run(tc.name, func(t *testing.T) {
			key, err := protoserialization.ParseKey(tc.privateKeySerialization)
			if err != nil {
				t.Fatalf("protoserialization.ParseKey() err = %v, want nil", err)
			}
			if diff := cmp.Diff(tc.privateKey, key, protocmp.Transform()); diff != "" {
				t.Errorf("unexpected diff (-want +got): %s", diff)
			}
		})
	}
}

func TestPrivateKeyParser_Errors(t *testing.T) {
	e := new(big.Int).SetInt64(f4).Bytes()
	for _, tc := range []struct {
		name                    string
		privateKeySerialization *protoserialization.KeySerialization
	}{
		{
			name: "wrong_key_material_type",
			privateKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1PrivateKey{
					Version: 0,
					PublicKey: &jwtrsapb.JwtRsaSsaPkcs1PublicKey{
						Version:   0,
						Algorithm: jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256,
						N:         mustBase64Decode(t, n2048Base64),
						E:         e,
					},
					D:   mustBase64Decode(t, d2048Base64),
					P:   mustBase64Decode(t, p2048Base64),
					Q:   mustBase64Decode(t, q2048Base64),
					Dp:  mustBase64Decode(t, dp2048Base64),
					Dq:  mustBase64Decode(t, dq2048Base64),
					Crt: mustBase64Decode(t, qInv2048Base64),
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 123),
		},
		{
			name: "invalid_proto_serialization",
			privateKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value:           []byte("invalid proto"),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 123),
		},
		{
			name: "invalid_private_key_version",
			privateKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value: mustMarshal(t, func() proto.Message {
					invalidProto := &jwtrsapb.JwtRsaSsaPkcs1PrivateKey{
						Version: 0,
						PublicKey: &jwtrsapb.JwtRsaSsaPkcs1PublicKey{
							Version:   0,
							Algorithm: jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256,
							N:         mustBase64Decode(t, n2048Base64),
							E:         e,
						},
						D:   mustBase64Decode(t, d2048Base64),
						P:   mustBase64Decode(t, p2048Base64),
						Q:   mustBase64Decode(t, q2048Base64),
						Dp:  mustBase64Decode(t, dp2048Base64),
						Dq:  mustBase64Decode(t, dq2048Base64),
						Crt: mustBase64Decode(t, qInv2048Base64),
					}
					invalidProto.Version = 1
					return invalidProto
				}()),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 123),
		},
		{
			name: "invalid_public_key_version",
			privateKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1PrivateKey{
					Version: 1,
					PublicKey: &jwtrsapb.JwtRsaSsaPkcs1PublicKey{
						Version:   0,
						Algorithm: jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256,
						N:         mustBase64Decode(t, n2048Base64),
						E:         e,
					},
					D:   mustBase64Decode(t, d2048Base64),
					P:   mustBase64Decode(t, p2048Base64),
					Q:   mustBase64Decode(t, q2048Base64),
					Dp:  mustBase64Decode(t, dp2048Base64),
					Dq:  mustBase64Decode(t, dq2048Base64),
					Crt: mustBase64Decode(t, qInv2048Base64),
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 123),
		},
		{
			name: "tink_with_custom_kid",
			privateKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1PrivateKey{
					Version: 0,
					PublicKey: &jwtrsapb.JwtRsaSsaPkcs1PublicKey{
						Version:   0,
						Algorithm: jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256,
						N:         mustBase64Decode(t, n2048Base64),
						E:         e,
						CustomKid: &jwtrsapb.JwtRsaSsaPkcs1PublicKey_CustomKid{Value: "custom123"},
					},
					D:   mustBase64Decode(t, d2048Base64),
					P:   mustBase64Decode(t, p2048Base64),
					Q:   mustBase64Decode(t, q2048Base64),
					Dp:  mustBase64Decode(t, dp2048Base64),
					Dq:  mustBase64Decode(t, dq2048Base64),
					Crt: mustBase64Decode(t, qInv2048Base64),
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 123),
		},
		{
			name: "mismatched_d",
			privateKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
				Value: mustMarshal(t, &jwtrsapb.JwtRsaSsaPkcs1PrivateKey{
					Version: 0,
					PublicKey: &jwtrsapb.JwtRsaSsaPkcs1PublicKey{
						Version:   0,
						Algorithm: jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256,
						N:         mustBase64Decode(t, n2048Base64),
						E:         e,
					},
					D:   mustBase64Decode(t, d3072Base64),
					P:   mustBase64Decode(t, p2048Base64),
					Q:   mustBase64Decode(t, q2048Base64),
					Dp:  mustBase64Decode(t, dp2048Base64),
					Dq:  mustBase64Decode(t, dq2048Base64),
					Crt: mustBase64Decode(t, qInv2048Base64),
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 123),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.ParseKey(tc.privateKeySerialization); err == nil {
				t.Errorf("protoserialization.ParseKey() err = nil, want err")
			} else {
				t.Logf("protoserialization.ParseKey() err = %v", err)
			}
		})
	}
}
