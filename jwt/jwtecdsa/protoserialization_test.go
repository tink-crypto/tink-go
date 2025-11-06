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
	"encoding/hex"
	"fmt"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/internal/ec"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtecdsa"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testutil/testonlyinsecuresecretdataaccess"

	jwtecdsapb "github.com/tink-crypto/tink-go/v2/proto/jwt_ecdsa_go_proto"
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

func TestParametersSerializer(t *testing.T) {
	for _, tc := range []struct {
		params *jwtecdsa.Parameters
		wantKt *tinkpb.KeyTemplate
	}{
		{
			params: mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES256),
			wantKt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaKeyFormat{
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
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaKeyFormat{
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
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaKeyFormat{
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
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaKeyFormat{
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
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaKeyFormat{
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
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaKeyFormat{
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
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaKeyFormat{
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
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaKeyFormat{
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
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaKeyFormat{
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
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaKeyFormat{
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
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaKeyFormat{
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
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaKeyFormat{
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
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaKeyFormat{
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
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaKeyFormat{
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
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaKeyFormat{
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
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaKeyFormat{
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
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaKeyFormat{
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
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaKeyFormat{
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
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaKeyFormat{
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

func mustNewKeySerialization(t *testing.T, keyData *tinkpb.KeyData, outputPrefixType tinkpb.OutputPrefixType, idRequirement uint32) *protoserialization.KeySerialization {
	t.Helper()
	keySerialization, err := protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
	if err != nil {
		t.Fatalf("protoserialization.NewKeySerialization() err = %v, want nil", err)
	}
	return keySerialization
}

func mustCreatePublicKey(t *testing.T, opts jwtecdsa.PublicKeyOpts) *jwtecdsa.PublicKey {
	t.Helper()
	key, err := jwtecdsa.NewPublicKey(opts)
	if err != nil {
		t.Fatalf("jwtecdsa.NewPublicKey() err = %v, want nil", err)
	}
	return key
}

type publicKeyTestCase struct {
	name                   string
	publicKey              *jwtecdsa.PublicKey
	publicKeySerialization *protoserialization.KeySerialization
}

func getPublicKeyTestCases(t *testing.T) []*publicKeyTestCase {
	return []*publicKeyTestCase{
		{
			name: fmt.Sprintf("%v_%v_TINK", jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES256),
			publicKey: mustCreatePublicKey(t, jwtecdsa.PublicKeyOpts{
				PublicPoint:   mustHexDecode(t, p256PublicKeyPointHex),
				IDRequirement: 12345,
				HasCustomKID:  false,
				Parameters:    mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES256),
			}),
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPublicKey{
					Version:   0,
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES256,
					X:         slices.Concat([]byte{0x00}, mustHexDecode(t, p256PublicKeyPointXHex)),
					Y:         slices.Concat([]byte{0x00}, mustHexDecode(t, p256PublicKeyPointYHex)),
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: fmt.Sprintf("%v_%v_RAW", jwtecdsa.IgnoredKID, jwtecdsa.ES256),
			publicKey: mustCreatePublicKey(t, jwtecdsa.PublicKeyOpts{
				PublicPoint:  mustHexDecode(t, p256PublicKeyPointHex),
				HasCustomKID: false,
				Parameters:   mustCreateParameters(t, jwtecdsa.IgnoredKID, jwtecdsa.ES256),
			}),
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPublicKey{
					Version:   0,
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES256,
					X:         slices.Concat([]byte{0x00}, mustHexDecode(t, p256PublicKeyPointXHex)),
					Y:         slices.Concat([]byte{0x00}, mustHexDecode(t, p256PublicKeyPointYHex)),
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: fmt.Sprintf("%v_%v_RAW", jwtecdsa.CustomKID, jwtecdsa.ES256),
			publicKey: mustCreatePublicKey(t, jwtecdsa.PublicKeyOpts{
				PublicPoint:  mustHexDecode(t, p256PublicKeyPointHex),
				HasCustomKID: true,
				CustomKID:    "myCustomKID",
				Parameters:   mustCreateParameters(t, jwtecdsa.CustomKID, jwtecdsa.ES256),
			}),
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPublicKey{
					Version:   0,
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES256,
					X:         slices.Concat([]byte{0x00}, mustHexDecode(t, p256PublicKeyPointXHex)),
					Y:         slices.Concat([]byte{0x00}, mustHexDecode(t, p256PublicKeyPointYHex)),
					CustomKid: &jwtecdsapb.JwtEcdsaPublicKey_CustomKid{Value: "myCustomKID"},
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		// ES384.
		{
			name: fmt.Sprintf("%v_%v_TINK", jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES384),
			publicKey: mustCreatePublicKey(t, jwtecdsa.PublicKeyOpts{
				PublicPoint:   mustHexDecode(t, p384PublicKeyPointHex),
				IDRequirement: 12345,
				HasCustomKID:  false,
				Parameters:    mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES384),
			}),
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPublicKey{
					Version:   0,
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES384,
					X:         slices.Concat([]byte{0x00}, mustHexDecode(t, p384PublicKeyPointXHex)),
					Y:         slices.Concat([]byte{0x00}, mustHexDecode(t, p384PublicKeyPointYHex)),
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: fmt.Sprintf("%v_%v_RAW", jwtecdsa.IgnoredKID, jwtecdsa.ES384),
			publicKey: mustCreatePublicKey(t, jwtecdsa.PublicKeyOpts{
				PublicPoint:  mustHexDecode(t, p384PublicKeyPointHex),
				HasCustomKID: false,
				Parameters:   mustCreateParameters(t, jwtecdsa.IgnoredKID, jwtecdsa.ES384),
			}),
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPublicKey{
					Version:   0,
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES384,
					X:         slices.Concat([]byte{0x00}, mustHexDecode(t, p384PublicKeyPointXHex)),
					Y:         slices.Concat([]byte{0x00}, mustHexDecode(t, p384PublicKeyPointYHex)),
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: fmt.Sprintf("%v_%v_RAW", jwtecdsa.CustomKID, jwtecdsa.ES384),
			publicKey: mustCreatePublicKey(t, jwtecdsa.PublicKeyOpts{
				PublicPoint:  mustHexDecode(t, p384PublicKeyPointHex),
				HasCustomKID: true,
				CustomKID:    "myCustomKID",
				Parameters:   mustCreateParameters(t, jwtecdsa.CustomKID, jwtecdsa.ES384),
			}),
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPublicKey{
					Version:   0,
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES384,
					X:         slices.Concat([]byte{0x00}, mustHexDecode(t, p384PublicKeyPointXHex)),
					Y:         slices.Concat([]byte{0x00}, mustHexDecode(t, p384PublicKeyPointYHex)),
					CustomKid: &jwtecdsapb.JwtEcdsaPublicKey_CustomKid{Value: "myCustomKID"},
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		// ES512.
		{
			name: fmt.Sprintf("%v_%v_TINK", jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES512),
			publicKey: mustCreatePublicKey(t, jwtecdsa.PublicKeyOpts{
				PublicPoint:   mustHexDecode(t, p521PublicKeyPointHex),
				IDRequirement: 12345,
				HasCustomKID:  false,
				Parameters:    mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES512),
			}),
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPublicKey{
					Version:   0,
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES512,
					X:         slices.Concat([]byte{0x00}, mustHexDecode(t, p521PublicKeyPointXHex)),
					Y:         slices.Concat([]byte{0x00}, mustHexDecode(t, p521PublicKeyPointYHex)),
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: fmt.Sprintf("%v_%v_RAW", jwtecdsa.IgnoredKID, jwtecdsa.ES512),
			publicKey: mustCreatePublicKey(t, jwtecdsa.PublicKeyOpts{
				PublicPoint:  mustHexDecode(t, p521PublicKeyPointHex),
				HasCustomKID: false,
				Parameters:   mustCreateParameters(t, jwtecdsa.IgnoredKID, jwtecdsa.ES512),
			}),
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPublicKey{
					Version:   0,
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES512,
					X:         slices.Concat([]byte{0x00}, mustHexDecode(t, p521PublicKeyPointXHex)),
					Y:         slices.Concat([]byte{0x00}, mustHexDecode(t, p521PublicKeyPointYHex)),
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: fmt.Sprintf("%v_%v_RAW", jwtecdsa.CustomKID, jwtecdsa.ES512),
			publicKey: mustCreatePublicKey(t, jwtecdsa.PublicKeyOpts{
				PublicPoint:  mustHexDecode(t, p521PublicKeyPointHex),
				HasCustomKID: true,
				CustomKID:    "myCustomKID",
				Parameters:   mustCreateParameters(t, jwtecdsa.CustomKID, jwtecdsa.ES512),
			}),
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPublicKey{
					Version:   0,
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES512,
					X:         slices.Concat([]byte{0x00}, mustHexDecode(t, p521PublicKeyPointXHex)),
					Y:         slices.Concat([]byte{0x00}, mustHexDecode(t, p521PublicKeyPointYHex)),
					CustomKid: &jwtecdsapb.JwtEcdsaPublicKey_CustomKid{Value: "myCustomKID"},
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: fmt.Sprintf("%v_%v_RAW_empty_custom_kid", jwtecdsa.CustomKID, jwtecdsa.ES512),
			publicKey: mustCreatePublicKey(t, jwtecdsa.PublicKeyOpts{
				PublicPoint:  mustHexDecode(t, p521PublicKeyPointHex),
				HasCustomKID: true,
				CustomKID:    "",
				Parameters:   mustCreateParameters(t, jwtecdsa.CustomKID, jwtecdsa.ES512),
			}),
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPublicKey{
					Version:   0,
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES512,
					X:         slices.Concat([]byte{0x00}, mustHexDecode(t, p521PublicKeyPointXHex)),
					Y:         slices.Concat([]byte{0x00}, mustHexDecode(t, p521PublicKeyPointYHex)),
					CustomKid: &jwtecdsapb.JwtEcdsaPublicKey_CustomKid{Value: ""},
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
	}
}

func TestPublicKeySerializer(t *testing.T) {
	for _, tc := range getPublicKeyTestCases(t) {
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
	for _, tc := range append(getPublicKeyTestCases(t), []*publicKeyTestCase{
		{
			name: fmt.Sprintf("%v_%v_TINK_point_no_leading_zeros", jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES256),
			publicKey: mustCreatePublicKey(t, jwtecdsa.PublicKeyOpts{
				PublicPoint:   mustHexDecode(t, p256PublicKeyPointHex),
				IDRequirement: 12345,
				HasCustomKID:  false,
				Parameters:    mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES256),
			}),
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPublicKey{
					Version:   0,
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES256,
					X:         mustHexDecode(t, p256PublicKeyPointXHex),
					Y:         mustHexDecode(t, p256PublicKeyPointYHex),
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: fmt.Sprintf("%v_%v_TINK_point_arbitrary_leading_zeros", jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES256),
			publicKey: mustCreatePublicKey(t, jwtecdsa.PublicKeyOpts{
				PublicPoint:   mustHexDecode(t, p256PublicKeyPointHex),
				IDRequirement: 12345,
				HasCustomKID:  false,
				Parameters:    mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES256),
			}),
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPublicKey{
					Version:   0,
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES256,
					X:         slices.Concat([]byte{0, 0, 0, 0, 0}, mustHexDecode(t, p256PublicKeyPointXHex)),
					Y:         slices.Concat([]byte{0, 0, 0, 0, 0}, mustHexDecode(t, p256PublicKeyPointYHex)),
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
	}...) {
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
	for _, tc := range []struct {
		name                   string
		publicKeySerialization *protoserialization.KeySerialization
	}{
		{
			name: "invalid_key_material_type",
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPublicKey{
					Version:   0,
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES512,
					X:         slices.Concat([]byte{0x00}, mustHexDecode(t, p521PublicKeyPointXHex)),
					Y:         slices.Concat([]byte{0x00}, mustHexDecode(t, p521PublicKeyPointYHex)),
					CustomKid: &jwtecdsapb.JwtEcdsaPublicKey_CustomKid{Value: "myCustomKID"},
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid_version",
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPublicKey{
					Version:   1,
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES512,
					X:         slices.Concat([]byte{0x00}, mustHexDecode(t, p521PublicKeyPointXHex)),
					Y:         slices.Concat([]byte{0x00}, mustHexDecode(t, p521PublicKeyPointYHex)),
					CustomKid: &jwtecdsapb.JwtEcdsaPublicKey_CustomKid{Value: "myCustomKID"},
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "unknown_algorithm",
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPublicKey{
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES_UNKNOWN,
					X:         slices.Concat([]byte{0x00}, mustHexDecode(t, p521PublicKeyPointXHex)),
					Y:         slices.Concat([]byte{0x00}, mustHexDecode(t, p521PublicKeyPointYHex)),
					CustomKid: &jwtecdsapb.JwtEcdsaPublicKey_CustomKid{Value: "myCustomKID"},
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "small_x_coordinate",
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPublicKey{
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES512,
					X:         mustHexDecode(t, p521PublicKeyPointXHex)[:60],
					Y:         slices.Concat([]byte{0x00}, mustHexDecode(t, p521PublicKeyPointYHex)),
					CustomKid: &jwtecdsapb.JwtEcdsaPublicKey_CustomKid{Value: "myCustomKID"},
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "small_y_coordinate",
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPublicKey{
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES512,
					X:         slices.Concat([]byte{0x00}, mustHexDecode(t, p521PublicKeyPointXHex)),
					Y:         mustHexDecode(t, p521PublicKeyPointYHex)[:60],
					CustomKid: &jwtecdsapb.JwtEcdsaPublicKey_CustomKid{Value: "myCustomKID"},
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "large_x_coordinate",
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPublicKey{
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES512,
					X:         slices.Concat([]byte{0x01}, mustHexDecode(t, p521PublicKeyPointXHex)),
					Y:         slices.Concat([]byte{0x00}, mustHexDecode(t, p521PublicKeyPointYHex)),
					CustomKid: &jwtecdsapb.JwtEcdsaPublicKey_CustomKid{Value: "myCustomKID"},
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "large_y_coordinate",
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPublicKey{
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES512,
					X:         slices.Concat([]byte{0x00}, mustHexDecode(t, p521PublicKeyPointXHex)),
					Y:         slices.Concat([]byte{0x01}, mustHexDecode(t, p521PublicKeyPointYHex)),
					CustomKid: &jwtecdsapb.JwtEcdsaPublicKey_CustomKid{Value: "myCustomKID"},
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid_point",
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPublicKey{
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES512,
					X:         slices.Concat([]byte{0x00}, mustHexDecode(t, p521PublicKeyPointXHex)),
					Y:         slices.Concat([]byte{0x00}, mustHexDecode(t, "00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A000000000000000000000000000000000000000000000000000")),
					CustomKid: &jwtecdsapb.JwtEcdsaPublicKey_CustomKid{Value: "myCustomKID"},
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "tink_with_custom_kid",
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPublicKey{
					Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES512,
					X:         slices.Concat([]byte{0x00}, mustHexDecode(t, p521PublicKeyPointXHex)),
					Y:         slices.Concat([]byte{0x00}, mustHexDecode(t, p521PublicKeyPointYHex)),
					CustomKid: &jwtecdsapb.JwtEcdsaPublicKey_CustomKid{Value: "myCustomKID"},
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 0),
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

type privateKeyTestCase struct {
	name                    string
	privateKey              *jwtecdsa.PrivateKey
	privateKeySerialization *protoserialization.KeySerialization
}

func coordinateSizeFromAlgorithm(t *testing.T, a jwtecdsa.Algorithm) int {
	t.Helper()
	switch a {
	case jwtecdsa.ES256:
		return 32
	case jwtecdsa.ES384:
		return 48
	case jwtecdsa.ES512:
		return 66
	}
	t.Fatalf("unknown algorithm: %v", a)
	return 0
}

func mustCreatePrivateKeyFromPublicKey(t *testing.T, keyBytes []byte, publicKey *jwtecdsa.PublicKey) *jwtecdsa.PrivateKey {
	t.Helper()
	secretDataKeyValue := secretdata.NewBytesFromData(keyBytes, testonlyinsecuresecretdataaccess.Token())
	privateKey, err := jwtecdsa.NewPrivateKeyFromPublicKey(secretDataKeyValue, publicKey)
	if err != nil {
		t.Fatalf("jwtecdsa.NewPrivateKeyFromPublicKey() err = %v, want nil", err)
	}
	return privateKey
}

func getPrivateKeyTestCases(t *testing.T) []*privateKeyTestCase {
	var testCases []*privateKeyTestCase
	for _, tc := range getPublicKeyTestCases(t) {
		var privateKeyHex string
		switch tc.publicKey.Parameters().(*jwtecdsa.Parameters).Algorithm() {
		case jwtecdsa.ES256:
			privateKeyHex = p256PrivateKeyHex
		case jwtecdsa.ES384:
			privateKeyHex = p384PrivateKeyHex
		case jwtecdsa.ES512:
			privateKeyHex = p521PrivateKeyHex
		}
		privateKeyBytes := mustHexDecode(t, privateKeyHex)
		privateKey := mustCreatePrivateKeyFromPublicKey(t, privateKeyBytes, tc.publicKey)

		protoPublicKey := &jwtecdsapb.JwtEcdsaPublicKey{}
		if err := proto.Unmarshal(tc.publicKeySerialization.KeyData().GetValue(), protoPublicKey); err != nil {
			t.Fatalf("proto.Unmarshal() err = %v, want nil", err)
		}

		coordinateSize := coordinateSizeFromAlgorithm(t, tc.publicKey.Parameters().(*jwtecdsa.Parameters).Algorithm())
		paddedPrivateKey, err := ec.BigIntBytesToFixedSizeBuffer(privateKeyBytes, coordinateSize+1)
		if err != nil {
			t.Fatalf("ec.BigIntBytesToFixedSizeBuffer() err = %v, want nil", err)
		}

		protoPrivateKey := &jwtecdsapb.JwtEcdsaPrivateKey{
			Version:   0,
			PublicKey: protoPublicKey,
			KeyValue:  paddedPrivateKey,
		}
		serializedPrivateKey, err := proto.Marshal(protoPrivateKey)
		if err != nil {
			t.Fatalf("proto.Marshal() err = %v, want nil", err)
		}

		idRequirement, _ := tc.publicKey.IDRequirement()
		privateKeySerialization, err := protoserialization.NewKeySerialization(
			&tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value:           serializedPrivateKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			},
			tc.publicKeySerialization.OutputPrefixType(),
			idRequirement,
		)
		if err != nil {
			t.Fatalf("protoserialization.NewKeySerialization() err = %v, want nil", err)
		}

		testCases = append(testCases, &privateKeyTestCase{
			name:                    tc.name,
			privateKey:              privateKey,
			privateKeySerialization: privateKeySerialization,
		})
	}
	return testCases
}

func TestPrivateKeySerializer(t *testing.T) {
	for _, tc := range getPrivateKeyTestCases(t) {
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
	unpaddedPrivKey, err := hex.DecodeString(p256PrivateKeyHex)
	if err != nil {
		t.Fatalf("hex.DecodeString() err = %v, want nil", err)
	}

	for _, tc := range append(getPrivateKeyTestCases(t), []*privateKeyTestCase{
		{
			name: "no_leading_zeros",
			privateKey: mustCreatePrivateKeyFromPublicKey(t, unpaddedPrivKey, mustCreatePublicKey(t, jwtecdsa.PublicKeyOpts{
				PublicPoint:   mustHexDecode(t, p256PublicKeyPointHex),
				IDRequirement: 12345,
				Parameters:    mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES256),
			})),
			privateKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPrivateKey{
					Version: 0,
					PublicKey: &jwtecdsapb.JwtEcdsaPublicKey{
						Version:   0,
						Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES256,
						X:         mustHexDecode(t, p256PublicKeyPointXHex),
						Y:         mustHexDecode(t, p256PublicKeyPointYHex),
					},
					KeyValue: unpaddedPrivKey,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "arbitrary_leading_zeros",
			privateKey: mustCreatePrivateKeyFromPublicKey(t, unpaddedPrivKey, mustCreatePublicKey(t, jwtecdsa.PublicKeyOpts{
				PublicPoint:   mustHexDecode(t, p256PublicKeyPointHex),
				IDRequirement: 12345,
				Parameters:    mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES256),
			})),
			privateKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPrivateKey{
					Version: 0,
					PublicKey: &jwtecdsapb.JwtEcdsaPublicKey{
						Version:   0,
						Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES256,
						X:         mustHexDecode(t, p256PublicKeyPointXHex),
						Y:         mustHexDecode(t, p256PublicKeyPointYHex),
					},
					KeyValue: slices.Concat([]byte{0, 0, 0, 0, 0}, unpaddedPrivKey),
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
	}...) {
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
	validPublicKeyProto := &jwtecdsapb.JwtEcdsaPublicKey{
		Version:   0,
		Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES256,
		X:         mustHexDecode(t, p256PublicKeyPointXHex),
		Y:         mustHexDecode(t, p256PublicKeyPointYHex),
	}
	paddedValidPrivateKeyBytes, err := ec.BigIntBytesToFixedSizeBuffer(mustHexDecode(t, p256PrivateKeyHex), 32+1)
	if err != nil {
		t.Fatal(err)
	}
	mismatchedPublicKeyProto := &jwtecdsapb.JwtEcdsaPublicKey{
		Version:   0,
		Algorithm: jwtecdsapb.JwtEcdsaAlgorithm_ES256,
		X:         mustHexDecode(t, "0000000000000000000000000000000000000000000000000000000000000000"),
		Y:         mustHexDecode(t, "0000000000000000000000000000000000000000000000000000000000000000"),
	}

	for _, tc := range []struct {
		name                    string
		privateKeySerialization *protoserialization.KeySerialization
	}{
		{
			name: "invalid_key_material_type",
			privateKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPrivateKey{
					Version:   0,
					PublicKey: validPublicKeyProto,
					KeyValue:  paddedValidPrivateKeyBytes,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "invalid_private_key_version",
			privateKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPrivateKey{
					Version:   1,
					PublicKey: validPublicKeyProto,
					KeyValue:  paddedValidPrivateKeyBytes,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "mismatched_public_private_key",
			privateKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPrivateKey{
					Version:   0,
					PublicKey: mismatchedPublicKeyProto,
					KeyValue:  paddedValidPrivateKeyBytes,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "private_key_too_long",
			privateKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPrivateKey{
					Version:   0,
					PublicKey: validPublicKeyProto,
					KeyValue:  append([]byte{0x01}, paddedValidPrivateKeyBytes...),
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "invalid_private_key_value",
			privateKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
				Value: mustMarshal(t, &jwtecdsapb.JwtEcdsaPrivateKey{
					Version:   0,
					PublicKey: validPublicKeyProto,
					KeyValue:  slices.Concat([]byte{0x01}, paddedValidPrivateKeyBytes[1:]),
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.ParseKey(tc.privateKeySerialization); err == nil {
				t.Error("protoserialization.ParseKey() err = nil, want error")
			} else {
				t.Logf("protoserialization.ParseKey() err = %v", err)
			}
		})
	}
}
