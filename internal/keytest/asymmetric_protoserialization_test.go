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
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/internal/keytest"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyset"
	testonlypb "github.com/tink-crypto/tink-go/v2/proto/test_only_key_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	testOnlyPublicKeyTypeURL  = "type.googleapis.com/google.crypto.tink.TestOnlyPublicKey"
	testOnlyPrivateKeyTypeURL = "type.googleapis.com/google.crypto.tink.TestOnlyPrivateKey"
)

// mustCreatePublicKeyData returns the serialization of a public key with the
// given key bytes.
func mustCreatePublicKeyData(t *testing.T, keyBytes []byte) *tinkpb.KeyData {
	t.Helper()
	return &tinkpb.KeyData{
		TypeUrl: testOnlyPublicKeyTypeURL,
		Value: mustMarshal(t, &testonlypb.TestOnlyPublicKey{
			Version:  0,
			KeyValue: keyBytes,
		}),
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}
}

// mustCreatePrivateKeyData returns the serialization of a private key with the
// given private and public key bytes.
func mustCreatePrivateKeyData(t *testing.T, privateKeyBytes, publicKeyBytes []byte) *tinkpb.KeyData {
	t.Helper()
	return &tinkpb.KeyData{
		TypeUrl: testOnlyPrivateKeyTypeURL,
		Value: mustMarshal(t, &testonlypb.TestOnlyPrivateKey{
			Version: 0,
			PublicKey: &testonlypb.TestOnlyPublicKey{
				Version:  0,
				KeyValue: publicKeyBytes,
			},
			KeyValue: privateKeyBytes,
		}),
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}
}

type asymmetricKeySerializationTestCase struct {
	name             string
	key              key.Key
	keySerialization *protoserialization.KeySerialization
}

// asymmetricKeySerializationTestCases returns public and private keys with
// their expected serialization, for each variant.
func asymmetricKeySerializationTestCases(t *testing.T) []asymmetricKeySerializationTestCase {
	t.Helper()
	publicKeyData := mustCreatePublicKeyData(t, key128Bits)
	privateKeyData := mustCreatePrivateKeyData(t, key128Bits, reversedKey128Bits)
	return []asymmetricKeySerializationTestCase{
		{
			name:             "public_key_TINK",
			key:              mustCreatePublicKey(t, keytest.VariantTink, 12345, key128Bits),
			keySerialization: mustCreateKeySerialization(t, publicKeyData, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name:             "public_key_CRUNCHY",
			key:              mustCreatePublicKey(t, keytest.VariantCrunchy, 12345, key128Bits),
			keySerialization: mustCreateKeySerialization(t, publicKeyData, tinkpb.OutputPrefixType_CRUNCHY, 12345),
		},
		{
			name:             "public_key_NO_PREFIX",
			key:              mustCreatePublicKey(t, keytest.VariantNoPrefix, 0, key128Bits),
			keySerialization: mustCreateKeySerialization(t, publicKeyData, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name:             "private_key_TINK",
			key:              mustCreatePrivateKey(t, keytest.VariantTink, 12345, key128Bits),
			keySerialization: mustCreateKeySerialization(t, privateKeyData, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name:             "private_key_CRUNCHY",
			key:              mustCreatePrivateKey(t, keytest.VariantCrunchy, 12345, key128Bits),
			keySerialization: mustCreateKeySerialization(t, privateKeyData, tinkpb.OutputPrefixType_CRUNCHY, 12345),
		},
		{
			name:             "private_key_NO_PREFIX",
			key:              mustCreatePrivateKey(t, keytest.VariantNoPrefix, 0, key128Bits),
			keySerialization: mustCreateKeySerialization(t, privateKeyData, tinkpb.OutputPrefixType_RAW, 0),
		},
	}
}

func TestSerializeAsymmetricKey(t *testing.T) {
	for _, tc := range asymmetricKeySerializationTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.SerializeKey(tc.key)
			if err != nil {
				t.Fatalf("protoserialization.SerializeKey(%v) err = %v, want nil", tc.key, err)
			}
			if !got.Equal(tc.keySerialization) {
				t.Errorf("protoserialization.SerializeKey(%v) = %v, want %v", tc.key, got, tc.keySerialization)
			}
		})
	}
}

func TestSerializeAsymmetricKeyFailsWithInvalidKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  key.Key
	}{
		{
			name: "public_key",
			key:  &keytest.PublicKey{},
		},
		{
			name: "private_key",
			key:  &keytest.PrivateKey{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.SerializeKey(tc.key); err == nil {
				t.Errorf("protoserialization.SerializeKey(%v) err = nil, want error", tc.key)
			}
		})
	}
}

func TestParseAsymmetricKey(t *testing.T) {
	testCases := asymmetricKeySerializationTestCases(t)
	// A key with output prefix type LEGACY is parsed as a key with variant
	// CRUNCHY, so this is not the serialization of the parsed key.
	testCases = append(testCases, []asymmetricKeySerializationTestCase{
		{
			name:             "public_key_LEGACY",
			key:              mustCreatePublicKey(t, keytest.VariantCrunchy, 12345, key128Bits),
			keySerialization: mustCreateKeySerialization(t, mustCreatePublicKeyData(t, key128Bits), tinkpb.OutputPrefixType_LEGACY, 12345),
		},
		{
			name:             "private_key_LEGACY",
			key:              mustCreatePrivateKey(t, keytest.VariantCrunchy, 12345, key128Bits),
			keySerialization: mustCreateKeySerialization(t, mustCreatePrivateKeyData(t, key128Bits, reversedKey128Bits), tinkpb.OutputPrefixType_LEGACY, 12345),
		},
	}...)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.ParseKey(tc.keySerialization)
			if err != nil {
				t.Fatalf("protoserialization.ParseKey(%v) err = %v, want nil", tc.keySerialization, err)
			}
			if !got.Equal(tc.key) {
				t.Errorf("protoserialization.ParseKey(%v) = %v, want %v", tc.keySerialization, got, tc.key)
			}
		})
	}
}

func TestSerializeAndParseAsymmetricKey(t *testing.T) {
	for _, tc := range keyTestCases() {
		privateKey := mustCreatePrivateKey(t, tc.variant, tc.keyID, tc.keyBytes)
		for _, keyTC := range []struct {
			name string
			key  key.Key
		}{
			{
				name: "private_key_" + tc.name,
				key:  privateKey,
			},
			{
				name: "public_key_" + tc.name,
				key:  mustGetPublicKey(t, privateKey),
			},
		} {
			t.Run(keyTC.name, func(t *testing.T) {
				k := keyTC.key
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
}

func TestParsePublicKeyFails(t *testing.T) {
	validKeyData := mustCreatePublicKeyData(t, key128Bits)
	for _, tc := range []struct {
		name             string
		keyData          *tinkpb.KeyData
		outputPrefixType tinkpb.OutputPrefixType
		keyID            uint32
	}{
		{
			name: "wrong_key_material_type",
			keyData: &tinkpb.KeyData{
				TypeUrl:         testOnlyPublicKeyTypeURL,
				Value:           validKeyData.GetValue(),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "wrong_version",
			keyData: &tinkpb.KeyData{
				TypeUrl: testOnlyPublicKeyTypeURL,
				Value: mustMarshal(t, &testonlypb.TestOnlyPublicKey{
					Version:  1,
					KeyValue: key128Bits,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name:             "key_too_short",
			keyData:          mustCreatePublicKeyData(t, key128Bits[:15]),
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name:             "key_too_long",
			keyData:          mustCreatePublicKeyData(t, key256Bits),
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name:             "unknown_output_prefix_type",
			keyData:          validKeyData,
			outputPrefixType: tinkpb.OutputPrefixType_UNKNOWN_PREFIX,
			keyID:            12345,
		},
		{
			name:             "zero_key_ID_with_TINK_output_prefix_type",
			keyData:          validKeyData,
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            0,
		},
		{
			name: "malformed_proto_key",
			keyData: &tinkpb.KeyData{
				TypeUrl:         testOnlyPublicKeyTypeURL,
				Value:           []byte("invalid proto"),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
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

func TestParsePrivateKeyFails(t *testing.T) {
	validKeyData := mustCreatePrivateKeyData(t, key128Bits, reversedKey128Bits)
	for _, tc := range []struct {
		name             string
		keyData          *tinkpb.KeyData
		outputPrefixType tinkpb.OutputPrefixType
		keyID            uint32
	}{
		{
			name: "wrong_key_material_type",
			keyData: &tinkpb.KeyData{
				TypeUrl:         testOnlyPrivateKeyTypeURL,
				Value:           validKeyData.GetValue(),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "wrong_version",
			keyData: &tinkpb.KeyData{
				TypeUrl: testOnlyPrivateKeyTypeURL,
				Value: mustMarshal(t, &testonlypb.TestOnlyPrivateKey{
					Version: 1,
					PublicKey: &testonlypb.TestOnlyPublicKey{
						Version:  0,
						KeyValue: reversedKey128Bits,
					},
					KeyValue: key128Bits,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "public_key_not_set",
			keyData: &tinkpb.KeyData{
				TypeUrl: testOnlyPrivateKeyTypeURL,
				Value: mustMarshal(t, &testonlypb.TestOnlyPrivateKey{
					Version:  0,
					KeyValue: key128Bits,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "wrong_public_key_version",
			keyData: &tinkpb.KeyData{
				TypeUrl: testOnlyPrivateKeyTypeURL,
				Value: mustMarshal(t, &testonlypb.TestOnlyPrivateKey{
					Version: 0,
					PublicKey: &testonlypb.TestOnlyPublicKey{
						Version:  1,
						KeyValue: reversedKey128Bits,
					},
					KeyValue: key128Bits,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			// The public key bytes are equal to the private key bytes, instead of
			// being in reverse order.
			name:             "public_key_does_not_match_private_key",
			keyData:          mustCreatePrivateKeyData(t, key128Bits, key128Bits),
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name:             "public_key_too_short",
			keyData:          mustCreatePrivateKeyData(t, key128Bits, reversedKey128Bits[:15]),
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			// The public key matches the private key, but both are too short.
			name:             "key_too_short",
			keyData:          mustCreatePrivateKeyData(t, key128Bits[1:], reversedKey128Bits[:15]),
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			// The public key matches the private key, but both are too long.
			name:             "key_too_long",
			keyData:          mustCreatePrivateKeyData(t, bytes.Repeat(key128Bits, 2), bytes.Repeat(reversedKey128Bits, 2)),
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name:             "unknown_output_prefix_type",
			keyData:          validKeyData,
			outputPrefixType: tinkpb.OutputPrefixType_UNKNOWN_PREFIX,
			keyID:            12345,
		},
		{
			name:             "zero_key_ID_with_TINK_output_prefix_type",
			keyData:          validKeyData,
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            0,
		},
		{
			name: "malformed_proto_key",
			keyData: &tinkpb.KeyData{
				TypeUrl:         testOnlyPrivateKeyTypeURL,
				Value:           []byte("invalid proto"),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
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

// mustCreateAsymmetricKeyTemplate returns a key template for test-only private
// keys.
func mustCreateAsymmetricKeyTemplate(t *testing.T, outputPrefixType tinkpb.OutputPrefixType, keySizeInBytes uint32) *tinkpb.KeyTemplate {
	t.Helper()
	return &tinkpb.KeyTemplate{
		TypeUrl:          testOnlyPrivateKeyTypeURL,
		OutputPrefixType: outputPrefixType,
		Value:            mustMarshal(t, &testonlypb.TestOnlyKeyFormat{KeySize: keySizeInBytes}),
	}
}

func TestSerializeAsymmetricParameters(t *testing.T) {
	for _, tc := range []struct {
		name            string
		parameters      *keytest.AsymmetricParameters
		wantKeyTemplate *tinkpb.KeyTemplate
	}{
		{
			name:            "TINK",
			parameters:      mustCreateAsymmetricParameters(t, keytest.VariantTink),
			wantKeyTemplate: mustCreateAsymmetricKeyTemplate(t, tinkpb.OutputPrefixType_TINK, 16),
		},
		{
			name:            "CRUNCHY",
			parameters:      mustCreateAsymmetricParameters(t, keytest.VariantCrunchy),
			wantKeyTemplate: mustCreateAsymmetricKeyTemplate(t, tinkpb.OutputPrefixType_CRUNCHY, 16),
		},
		{
			name:            "NO_PREFIX",
			parameters:      mustCreateAsymmetricParameters(t, keytest.VariantNoPrefix),
			wantKeyTemplate: mustCreateAsymmetricKeyTemplate(t, tinkpb.OutputPrefixType_RAW, 16),
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

func TestSerializeAsymmetricParametersFailsWithInvalidParameters(t *testing.T) {
	params := &keytest.AsymmetricParameters{}
	if _, err := protoserialization.SerializeParameters(params); err == nil {
		t.Errorf("protoserialization.SerializeParameters(%v) err = nil, want error", params)
	}
}

func TestParseAsymmetricParameters(t *testing.T) {
	for _, tc := range []struct {
		name           string
		keyTemplate    *tinkpb.KeyTemplate
		wantParameters *keytest.AsymmetricParameters
	}{
		{
			name:           "TINK",
			keyTemplate:    mustCreateAsymmetricKeyTemplate(t, tinkpb.OutputPrefixType_TINK, 16),
			wantParameters: mustCreateAsymmetricParameters(t, keytest.VariantTink),
		},
		{
			name:           "CRUNCHY",
			keyTemplate:    mustCreateAsymmetricKeyTemplate(t, tinkpb.OutputPrefixType_CRUNCHY, 16),
			wantParameters: mustCreateAsymmetricParameters(t, keytest.VariantCrunchy),
		},
		{
			name:           "LEGACY",
			keyTemplate:    mustCreateAsymmetricKeyTemplate(t, tinkpb.OutputPrefixType_LEGACY, 16),
			wantParameters: mustCreateAsymmetricParameters(t, keytest.VariantCrunchy),
		},
		{
			name:           "RAW",
			keyTemplate:    mustCreateAsymmetricKeyTemplate(t, tinkpb.OutputPrefixType_RAW, 16),
			wantParameters: mustCreateAsymmetricParameters(t, keytest.VariantNoPrefix),
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

func TestParseAsymmetricParametersFails(t *testing.T) {
	for _, tc := range []struct {
		name        string
		keyTemplate *tinkpb.KeyTemplate
	}{
		{
			name:        "key_size_not_set",
			keyTemplate: mustCreateAsymmetricKeyTemplate(t, tinkpb.OutputPrefixType_TINK, 0),
		},
		{
			name:        "wrong_key_size",
			keyTemplate: mustCreateAsymmetricKeyTemplate(t, tinkpb.OutputPrefixType_TINK, 32),
		},
		{
			name:        "unknown_output_prefix_type",
			keyTemplate: mustCreateAsymmetricKeyTemplate(t, tinkpb.OutputPrefixType_UNKNOWN_PREFIX, 16),
		},
		{
			name: "malformed_proto_format",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl:          testOnlyPrivateKeyTypeURL,
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				Value:            []byte("invalid format"),
			},
		},
		{
			// Keys are generated from templates of the private key type only.
			name: "public_key_type_URL",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl:          testOnlyPublicKeyTypeURL,
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				Value:            mustMarshal(t, &testonlypb.TestOnlyKeyFormat{KeySize: 16}),
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

// mustCreatePrivateKeyHandle returns a handle with a single new private key
// with the given variant.
func mustCreatePrivateKeyHandle(t *testing.T, variant keytest.Variant) *keyset.Handle {
	t.Helper()
	params := mustCreateAsymmetricParameters(t, variant)
	manager := keyset.NewManager()
	keyID, err := manager.AddNewKeyFromParameters(params)
	if err != nil {
		t.Fatalf("manager.AddNewKeyFromParameters(%v) err = %v, want nil", params, err)
	}
	if err := manager.SetPrimary(keyID); err != nil {
		t.Fatalf("manager.SetPrimary(%v) err = %v, want nil", keyID, err)
	}
	handle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}
	return handle
}

func mustGetPrimaryKey(t *testing.T, handle *keyset.Handle) key.Key {
	t.Helper()
	entry, err := handle.Primary()
	if err != nil {
		t.Fatalf("handle.Primary() err = %v, want nil", err)
	}
	return entry.Key()
}

func TestAsymmetricKeysHandleFromParameters(t *testing.T) {
	for _, variant := range []keytest.Variant{
		keytest.VariantTink,
		keytest.VariantCrunchy,
		keytest.VariantNoPrefix,
	} {
		t.Run(variant.String(), func(t *testing.T) {
			params := mustCreateAsymmetricParameters(t, variant)
			handle := mustCreatePrivateKeyHandle(t, variant)
			privateKey, ok := mustGetPrimaryKey(t, handle).(*keytest.PrivateKey)
			if !ok {
				t.Fatalf("handle.Primary().Key() is of type %T, want %T", mustGetPrimaryKey(t, handle), (*keytest.PrivateKey)(nil))
			}
			if !privateKey.Parameters().Equal(params) {
				t.Errorf("privateKey.Parameters() = %v, want %v", privateKey.Parameters(), params)
			}
			if got, want := handle.KeysetInfo().GetKeyInfo()[0].GetTypeUrl(), testOnlyPrivateKeyTypeURL; got != want {
				t.Errorf("handle.KeysetInfo().GetKeyInfo()[0].GetTypeUrl() = %q, want %q", got, want)
			}

			publicHandle, err := handle.Public()
			if err != nil {
				t.Fatalf("handle.Public() err = %v, want nil", err)
			}
			publicKey, ok := mustGetPrimaryKey(t, publicHandle).(*keytest.PublicKey)
			if !ok {
				t.Fatalf("publicHandle.Primary().Key() is of type %T, want %T", mustGetPrimaryKey(t, publicHandle), (*keytest.PublicKey)(nil))
			}
			if want := mustGetPublicKey(t, privateKey); !publicKey.Equal(want) {
				t.Errorf("publicHandle.Primary().Key() = %v, want %v", publicKey, want)
			}
			if got, want := publicHandle.KeysetInfo().GetKeyInfo()[0].GetTypeUrl(), testOnlyPublicKeyTypeURL; got != want {
				t.Errorf("publicHandle.KeysetInfo().GetKeyInfo()[0].GetTypeUrl() = %q, want %q", got, want)
			}
		})
	}
}

func TestPrivateKeyHandleWriteRead(t *testing.T) {
	for _, variant := range []keytest.Variant{
		keytest.VariantTink,
		keytest.VariantCrunchy,
		keytest.VariantNoPrefix,
	} {
		t.Run(variant.String(), func(t *testing.T) {
			handle := mustCreatePrivateKeyHandle(t, variant)
			buf := new(bytes.Buffer)
			if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buf)); err != nil {
				t.Fatalf("insecurecleartextkeyset.Write(handle, w) err = %v, want nil", err)
			}
			parsedHandle, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buf))
			if err != nil {
				t.Fatalf("insecurecleartextkeyset.Read(r) err = %v, want nil", err)
			}
			if diff := cmp.Diff(handle.KeysetInfo(), parsedHandle.KeysetInfo(), protocmp.Transform()); diff != "" {
				t.Errorf("parsedHandle.KeysetInfo() returned unexpected diff (-want +got):\n%s", diff)
			}
			if got, want := mustGetPrimaryKey(t, parsedHandle), mustGetPrimaryKey(t, handle); !got.Equal(want) {
				t.Errorf("parsedHandle.Primary().Key() = %v, want %v", got, want)
			}
		})
	}
}

func TestPrivateKeyHandleWriteWithNoSecretsFails(t *testing.T) {
	handle := mustCreatePrivateKeyHandle(t, keytest.VariantTink)
	buf := new(bytes.Buffer)
	if err := handle.WriteWithNoSecrets(keyset.NewBinaryWriter(buf)); err == nil {
		t.Errorf("handle.WriteWithNoSecrets(w) err = nil, want error")
	}
}

func TestPublicKeyHandleWriteReadWithNoSecrets(t *testing.T) {
	for _, variant := range []keytest.Variant{
		keytest.VariantTink,
		keytest.VariantCrunchy,
		keytest.VariantNoPrefix,
	} {
		t.Run(variant.String(), func(t *testing.T) {
			publicHandle, err := mustCreatePrivateKeyHandle(t, variant).Public()
			if err != nil {
				t.Fatalf("handle.Public() err = %v, want nil", err)
			}
			buf := new(bytes.Buffer)
			if err := publicHandle.WriteWithNoSecrets(keyset.NewBinaryWriter(buf)); err != nil {
				t.Fatalf("publicHandle.WriteWithNoSecrets(w) err = %v, want nil", err)
			}
			parsedHandle, err := keyset.ReadWithNoSecrets(keyset.NewBinaryReader(buf))
			if err != nil {
				t.Fatalf("keyset.ReadWithNoSecrets(r) err = %v, want nil", err)
			}
			if diff := cmp.Diff(publicHandle.KeysetInfo(), parsedHandle.KeysetInfo(), protocmp.Transform()); diff != "" {
				t.Errorf("parsedHandle.KeysetInfo() returned unexpected diff (-want +got):\n%s", diff)
			}
			if got, want := mustGetPrimaryKey(t, parsedHandle), mustGetPrimaryKey(t, publicHandle); !got.Equal(want) {
				t.Errorf("parsedHandle.Primary().Key() = %v, want %v", got, want)
			}
		})
	}
}
