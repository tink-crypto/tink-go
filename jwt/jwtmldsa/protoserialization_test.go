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

package jwtmldsa_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtmldsa"

	jwtmldsapb "github.com/tink-crypto/tink-go/v2/proto/jwt_ml_dsa_go_proto"
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
		params *jwtmldsa.Parameters
		wantKt *tinkpb.KeyTemplate
	}{
		{
			params: mustCreateParameters(t, jwtmldsa.Base64EncodedKeyIDAsKID, jwtmldsa.MLDSA44),
			wantKt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtMlDsaPrivateKey",
				Value: mustMarshal(t, &jwtmldsapb.JwtMlDsaKeyFormat{
					Algorithm: jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA44,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			params: mustCreateParameters(t, jwtmldsa.IgnoredKID, jwtmldsa.MLDSA65),
			wantKt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtMlDsaPrivateKey",
				Value: mustMarshal(t, &jwtmldsapb.JwtMlDsaKeyFormat{
					Algorithm: jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA65,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			params: mustCreateParameters(t, jwtmldsa.CustomKID, jwtmldsa.MLDSA87),
			wantKt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtMlDsaPrivateKey",
				Value: mustMarshal(t, &jwtmldsapb.JwtMlDsaKeyFormat{
					Algorithm: jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA87,
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
		wantParams *jwtmldsa.Parameters
		kt         *tinkpb.KeyTemplate
	}{
		{
			wantParams: mustCreateParameters(t, jwtmldsa.Base64EncodedKeyIDAsKID, jwtmldsa.MLDSA44),
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtMlDsaPrivateKey",
				Value: mustMarshal(t, &jwtmldsapb.JwtMlDsaKeyFormat{
					Algorithm: jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA44,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			wantParams: mustCreateParameters(t, jwtmldsa.IgnoredKID, jwtmldsa.MLDSA65),
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtMlDsaPrivateKey",
				Value: mustMarshal(t, &jwtmldsapb.JwtMlDsaKeyFormat{
					Algorithm: jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA65,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			wantParams: mustCreateParameters(t, jwtmldsa.IgnoredKID, jwtmldsa.MLDSA87),
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtMlDsaPrivateKey",
				Value: mustMarshal(t, &jwtmldsapb.JwtMlDsaKeyFormat{
					Algorithm: jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA87,
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
			if diff := cmp.Diff(tc.wantParams, got, cmp.AllowUnexported(jwtmldsa.Parameters{})); diff != "" {
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
				TypeUrl:          "type.googleapis.com/google.crypto.tink.JwtMlDsaPrivateKey",
				Value:            nil,
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "unknown output prefix type",
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtMlDsaPrivateKey",
				Value: mustMarshal(t, &jwtmldsapb.JwtMlDsaKeyFormat{
					Algorithm: jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA44,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_UNKNOWN_PREFIX,
			},
		},
		{
			name: "invalid output prefix type",
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtMlDsaPrivateKey",
				Value: mustMarshal(t, &jwtmldsapb.JwtMlDsaKeyFormat{
					Algorithm: jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA44,
					Version:   0,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_CRUNCHY,
			},
		},
		{
			name: "invalid version",
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtMlDsaPrivateKey",
				Value: mustMarshal(t, &jwtmldsapb.JwtMlDsaKeyFormat{
					Algorithm: jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA44,
					Version:   1,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "invalid algorithm",
			kt: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtMlDsaPrivateKey",
				Value: mustMarshal(t, &jwtmldsapb.JwtMlDsaKeyFormat{
					Algorithm: jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA_UNKNOWN,
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

type publicKeyTestCase struct {
	name                   string
	publicKey              *jwtmldsa.PublicKey
	publicKeyOpts          jwtmldsa.PublicKeyOpts
	publicKeySerialization *protoserialization.KeySerialization
}

func getPublicKeyTestCases(t *testing.T) []*publicKeyTestCase {
	pubBytes44 := mustHexDecode(t, mldsa44PublicKeyHex)
	pubBytes65 := mustHexDecode(t, mldsa65PublicKeyHex)
	pubBytes87 := mustHexDecode(t, mldsa87PublicKeyHex)
	return []*publicKeyTestCase{
		{
			name: "Base64EncodedKeyIDAsKID_MLDSA44_TINK",
			publicKey: mustCreatePublicKey(t, jwtmldsa.PublicKeyOpts{
				KeyBytes:      pubBytes44,
				IDRequirement: 12345,
				HasCustomKID:  false,
				Parameters:    mustCreateParameters(t, jwtmldsa.Base64EncodedKeyIDAsKID, jwtmldsa.MLDSA44),
			}),
			publicKeyOpts: jwtmldsa.PublicKeyOpts{
				KeyBytes:      pubBytes44,
				IDRequirement: 12345,
				HasCustomKID:  false,
				Parameters:    mustCreateParameters(t, jwtmldsa.Base64EncodedKeyIDAsKID, jwtmldsa.MLDSA44),
			},
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtMlDsaPublicKey",
				Value: mustMarshal(t, &jwtmldsapb.JwtMlDsaPublicKey{
					Version:   0,
					Algorithm: jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA44,
					KeyValue:  pubBytes44,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "IgnoredKID_MLDSA44_RAW",
			publicKey: mustCreatePublicKey(t, jwtmldsa.PublicKeyOpts{
				KeyBytes:     pubBytes44,
				HasCustomKID: false,
				Parameters:   mustCreateParameters(t, jwtmldsa.IgnoredKID, jwtmldsa.MLDSA44),
			}),
			publicKeyOpts: jwtmldsa.PublicKeyOpts{
				KeyBytes:     pubBytes44,
				HasCustomKID: false,
				Parameters:   mustCreateParameters(t, jwtmldsa.IgnoredKID, jwtmldsa.MLDSA44),
			},
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtMlDsaPublicKey",
				Value: mustMarshal(t, &jwtmldsapb.JwtMlDsaPublicKey{
					Version:   0,
					Algorithm: jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA44,
					KeyValue:  pubBytes44,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "Base64EncodedKeyIDAsKID_MLDSA65_TINK",
			publicKey: mustCreatePublicKey(t, jwtmldsa.PublicKeyOpts{
				KeyBytes:      pubBytes65,
				IDRequirement: 12345,
				HasCustomKID:  false,
				CustomKID:     "",
				Parameters:    mustCreateParameters(t, jwtmldsa.Base64EncodedKeyIDAsKID, jwtmldsa.MLDSA65),
			}),
			publicKeyOpts: jwtmldsa.PublicKeyOpts{
				KeyBytes:      pubBytes65,
				IDRequirement: 12345,
				HasCustomKID:  false,
				CustomKID:     "",
				Parameters:    mustCreateParameters(t, jwtmldsa.Base64EncodedKeyIDAsKID, jwtmldsa.MLDSA65),
			},
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtMlDsaPublicKey",
				Value: mustMarshal(t, &jwtmldsapb.JwtMlDsaPublicKey{
					Version:   0,
					Algorithm: jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA65,
					KeyValue:  pubBytes65,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "Base64EncodedKeyIDAsKID_MLDSA87_TINK",
			publicKey: mustCreatePublicKey(t, jwtmldsa.PublicKeyOpts{
				KeyBytes:      pubBytes87,
				IDRequirement: 12345,
				HasCustomKID:  false,
				CustomKID:     "",
				Parameters:    mustCreateParameters(t, jwtmldsa.Base64EncodedKeyIDAsKID, jwtmldsa.MLDSA87),
			}),
			publicKeyOpts: jwtmldsa.PublicKeyOpts{
				KeyBytes:      pubBytes87,
				IDRequirement: 12345,
				HasCustomKID:  false,
				CustomKID:     "",
				Parameters:    mustCreateParameters(t, jwtmldsa.Base64EncodedKeyIDAsKID, jwtmldsa.MLDSA87),
			},
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtMlDsaPublicKey",
				Value: mustMarshal(t, &jwtmldsapb.JwtMlDsaPublicKey{
					Version:   0,
					Algorithm: jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA87,
					KeyValue:  pubBytes87,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "IgnoredKID_MLDSA65_RAW",
			publicKey: mustCreatePublicKey(t, jwtmldsa.PublicKeyOpts{
				KeyBytes:     pubBytes65,
				HasCustomKID: false,
				Parameters:   mustCreateParameters(t, jwtmldsa.IgnoredKID, jwtmldsa.MLDSA65),
			}),
			publicKeyOpts: jwtmldsa.PublicKeyOpts{
				KeyBytes:     pubBytes65,
				HasCustomKID: false,
				Parameters:   mustCreateParameters(t, jwtmldsa.IgnoredKID, jwtmldsa.MLDSA65),
			},
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtMlDsaPublicKey",
				Value: mustMarshal(t, &jwtmldsapb.JwtMlDsaPublicKey{
					Version:   0,
					Algorithm: jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA65,
					KeyValue:  pubBytes65,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "IgnoredKID_MLDSA87_RAW",
			publicKey: mustCreatePublicKey(t, jwtmldsa.PublicKeyOpts{
				KeyBytes:     pubBytes87,
				HasCustomKID: false,
				Parameters:   mustCreateParameters(t, jwtmldsa.IgnoredKID, jwtmldsa.MLDSA87),
			}),
			publicKeyOpts: jwtmldsa.PublicKeyOpts{
				KeyBytes:     pubBytes87,
				HasCustomKID: false,
				Parameters:   mustCreateParameters(t, jwtmldsa.IgnoredKID, jwtmldsa.MLDSA87),
			},
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtMlDsaPublicKey",
				Value: mustMarshal(t, &jwtmldsapb.JwtMlDsaPublicKey{
					Version:   0,
					Algorithm: jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA87,
					KeyValue:  pubBytes87,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "CustomKID_MLDSA44_RAW",
			publicKey: mustCreatePublicKey(t, jwtmldsa.PublicKeyOpts{
				KeyBytes:     pubBytes44,
				HasCustomKID: true,
				CustomKID:    "myCustomKID",
				Parameters:   mustCreateParameters(t, jwtmldsa.CustomKID, jwtmldsa.MLDSA44),
			}),
			publicKeyOpts: jwtmldsa.PublicKeyOpts{
				KeyBytes:     pubBytes44,
				HasCustomKID: true,
				CustomKID:    "myCustomKID",
				Parameters:   mustCreateParameters(t, jwtmldsa.CustomKID, jwtmldsa.MLDSA44),
			},
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtMlDsaPublicKey",
				Value: mustMarshal(t, &jwtmldsapb.JwtMlDsaPublicKey{
					Version:   0,
					Algorithm: jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA44,
					KeyValue:  pubBytes44,
					CustomKid: &jwtmldsapb.JwtMlDsaPublicKey_CustomKid{Value: "myCustomKID"},
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "CustomKID_MLDSA65_RAW",
			publicKey: mustCreatePublicKey(t, jwtmldsa.PublicKeyOpts{
				KeyBytes:     pubBytes65,
				HasCustomKID: true,
				CustomKID:    "myCustomKID",
				Parameters:   mustCreateParameters(t, jwtmldsa.CustomKID, jwtmldsa.MLDSA65),
			}),
			publicKeyOpts: jwtmldsa.PublicKeyOpts{
				KeyBytes:     pubBytes65,
				HasCustomKID: true,
				CustomKID:    "myCustomKID",
				Parameters:   mustCreateParameters(t, jwtmldsa.CustomKID, jwtmldsa.MLDSA65),
			},
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtMlDsaPublicKey",
				Value: mustMarshal(t, &jwtmldsapb.JwtMlDsaPublicKey{
					Version:   0,
					Algorithm: jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA65,
					KeyValue:  pubBytes65,
					CustomKid: &jwtmldsapb.JwtMlDsaPublicKey_CustomKid{Value: "myCustomKID"},
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "CustomKID_MLDSA87_RAW",
			publicKey: mustCreatePublicKey(t, jwtmldsa.PublicKeyOpts{
				KeyBytes:     pubBytes87,
				HasCustomKID: true,
				CustomKID:    "myCustomKID",
				Parameters:   mustCreateParameters(t, jwtmldsa.CustomKID, jwtmldsa.MLDSA87),
			}),
			publicKeyOpts: jwtmldsa.PublicKeyOpts{
				KeyBytes:     pubBytes87,
				HasCustomKID: true,
				CustomKID:    "myCustomKID",
				Parameters:   mustCreateParameters(t, jwtmldsa.CustomKID, jwtmldsa.MLDSA87),
			},
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtMlDsaPublicKey",
				Value: mustMarshal(t, &jwtmldsapb.JwtMlDsaPublicKey{
					Version:   0,
					Algorithm: jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA87,
					KeyValue:  pubBytes87,
					CustomKid: &jwtmldsapb.JwtMlDsaPublicKey_CustomKid{Value: "myCustomKID"},
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
	for _, tc := range getPublicKeyTestCases(t) {
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
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtMlDsaPublicKey",
				Value: mustMarshal(t, &jwtmldsapb.JwtMlDsaPublicKey{
					Version:   0,
					Algorithm: jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA44,
					KeyValue:  mustHexDecode(t, mldsa44PublicKeyHex),
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid_key_material",
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtMlDsaPublicKey",
				Value: mustMarshal(t, &jwtmldsapb.JwtMlDsaPublicKey{
					Version:   0,
					Algorithm: jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA44,
					KeyValue:  []byte{1, 2, 3, 4},
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid_version",
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtMlDsaPublicKey",
				Value: mustMarshal(t, &jwtmldsapb.JwtMlDsaPublicKey{
					Version:   1,
					Algorithm: jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA44,
					KeyValue:  mustHexDecode(t, mldsa44PublicKeyHex),
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "unknown_algorithm",
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtMlDsaPublicKey",
				Value: mustMarshal(t, &jwtmldsapb.JwtMlDsaPublicKey{
					Algorithm: jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA_UNKNOWN,
					KeyValue:  mustHexDecode(t, mldsa44PublicKeyHex),
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "tink_with_custom_kid",
			publicKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtMlDsaPublicKey",
				Value: mustMarshal(t, &jwtmldsapb.JwtMlDsaPublicKey{
					Algorithm: jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA44,
					KeyValue:  mustHexDecode(t, mldsa44PublicKeyHex),
					CustomKid: &jwtmldsapb.JwtMlDsaPublicKey_CustomKid{Value: "myCustomKID"},
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 0),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.ParseKey(tc.publicKeySerialization); err == nil {
				t.Error("protoserialization.ParseKey() err = nil, want error")
			}
		})
	}
}

type privateKeyTestCase struct {
	name                    string
	privateKey              *jwtmldsa.PrivateKey
	privateKeySerialization *protoserialization.KeySerialization
}

func getPrivateKeyTestCases(t *testing.T) []*privateKeyTestCase {
	var testCases []*privateKeyTestCase
	for _, pubTc := range getPublicKeyTestCases(t) {
		var seedHex, pubKeyHex string
		switch pubTc.publicKeyOpts.Parameters.Algorithm() {
		case jwtmldsa.MLDSA44:
			seedHex, pubKeyHex = mldsa44SeedHex, mldsa44PublicKeyHex
		case jwtmldsa.MLDSA65:
			seedHex, pubKeyHex = mldsa65SeedHex, mldsa65PublicKeyHex
		case jwtmldsa.MLDSA87:
			seedHex, pubKeyHex = mldsa87SeedHex, mldsa87PublicKeyHex
		default:
			t.Fatalf("unknown algorithm: %v", pubTc.publicKeyOpts.Parameters.Algorithm())
		}

		privateKeyBytes := mustHexDecode(t, seedHex)
		privateKey := mustCreatePrivateKey(t, seedHex, pubKeyHex, pubTc.publicKeyOpts)

		protoPublicKey := &jwtmldsapb.JwtMlDsaPublicKey{}
		if err := proto.Unmarshal(pubTc.publicKeySerialization.KeyData().GetValue(), protoPublicKey); err != nil {
			t.Fatalf("proto.Unmarshal() err = %v, want nil", err)
		}

		protoPrivateKey := &jwtmldsapb.JwtMlDsaPrivateKey{
			Version:   0,
			PublicKey: protoPublicKey,
			KeyValue:  privateKeyBytes,
		}
		serializedPrivateKey, err := proto.Marshal(protoPrivateKey)
		if err != nil {
			t.Fatalf("proto.Marshal() err = %v, want nil", err)
		}

		idRequirement, _ := pubTc.publicKey.IDRequirement()
		testCases = append(testCases, &privateKeyTestCase{
			name:       pubTc.name,
			privateKey: privateKey,
			privateKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.JwtMlDsaPrivateKey",
				Value:           serializedPrivateKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, pubTc.publicKeySerialization.OutputPrefixType(), idRequirement),
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
	for _, tc := range getPrivateKeyTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.ParseKey(tc.privateKeySerialization)
			if err != nil {
				t.Fatalf("protoserialization.ParseKey() err = %v, want nil", err)
			}
			if diff := cmp.Diff(tc.privateKey, got, protocmp.Transform(), cmp.AllowUnexported(protoserialization.KeySerialization{})); diff != "" {
				t.Errorf("unexpected diff (-want +got): %s", diff)
			}
		})
	}
}

func TestPrivateKeyParser_Errors(t *testing.T) {
	protoPublicKey := &jwtmldsapb.JwtMlDsaPublicKey{
		Version:   0,
		Algorithm: jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA44,
		KeyValue:  mustHexDecode(t, mldsa44PublicKeyHex),
	}

	for _, tc := range []struct {
		name                    string
		privateKeySerialization *protoserialization.KeySerialization
	}{
		{
			name: "invalid_key_material_type",
			privateKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtMlDsaPrivateKey",
				Value: mustMarshal(t, &jwtmldsapb.JwtMlDsaPrivateKey{
					Version:   0,
					PublicKey: protoPublicKey,
					KeyValue:  mustHexDecode(t, mldsa44SeedHex),
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid_version",
			privateKeySerialization: mustNewKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.JwtMlDsaPrivateKey",
				Value: mustMarshal(t, &jwtmldsapb.JwtMlDsaPrivateKey{
					Version:   1,
					PublicKey: protoPublicKey,
					KeyValue:  mustHexDecode(t, mldsa44SeedHex),
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.ParseKey(tc.privateKeySerialization); err == nil {
				t.Error("protoserialization.ParseKey() err = nil, want error")
			}
		})
	}
}
