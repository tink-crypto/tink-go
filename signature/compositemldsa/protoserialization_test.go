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

package compositemldsa

import (
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	compmldsainternal "github.com/tink-crypto/tink-go/v2/internal/signature/compositemldsa"
	compmldsatestvectors "github.com/tink-crypto/tink-go/v2/internal/signature/compositemldsa/testing"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/signature/ecdsa"
	"github.com/tink-crypto/tink-go/v2/signature/mldsa"

	compositemldsapb "github.com/tink-crypto/tink-go/v2/proto/composite_ml_dsa_go_proto"
	mldsapb "github.com/tink-crypto/tink-go/v2/proto/ml_dsa_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func mustCreateKeySerialization(t *testing.T, keyData *tinkpb.KeyData, outputPrefixType tinkpb.OutputPrefixType, idRequirement uint32) *protoserialization.KeySerialization {
	t.Helper()
	ks, err := protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
	if err != nil {
		t.Fatalf("protoserialization.NewKeySerialization(%v, %v, %v) err = %v", keyData, outputPrefixType, idRequirement, err)
	}
	return ks
}

func mustMarshal(t *testing.T, message proto.Message) []byte {
	t.Helper()
	out, err := proto.Marshal(message)
	if err != nil {
		t.Fatalf("proto.Marshal err = %v", err)
	}
	return out
}

func mustSerializeKey(t *testing.T, k key.Key) []byte {
	t.Helper()
	if k == nil {
		return nil
	}
	s, err := protoserialization.SerializeKey(k)
	if err != nil {
		t.Fatalf("protoserialization.SerializeKey err = %v", err)
	}
	return s.KeyData().GetValue()
}

func mustCreateMLDSAKey(t *testing.T, instance MLDSAInstance, alg ClassicalAlgorithm) *mldsa.PublicKey {
	t.Helper()
	k, _ := compmldsatestvectors.CreatePublicKeyDeterministic(t, compmldsainternal.MLDSAInstance(instance), compmldsainternal.ClassicalAlgorithm(alg))
	return k
}

func mustCreateECDSAKey(t *testing.T, instance MLDSAInstance, alg ClassicalAlgorithm) *ecdsa.PublicKey {
	t.Helper()
	_, k := compmldsatestvectors.CreatePublicKeyDeterministic(t, compmldsainternal.MLDSAInstance(instance), compmldsainternal.ClassicalAlgorithm(alg))
	if k == nil {
		return nil
	}
	return k.(*ecdsa.PublicKey)
}

func mustMarshalECDSAPublicKey(t *testing.T, instance MLDSAInstance, alg ClassicalAlgorithm) []byte {
	t.Helper()
	return mustSerializeKey(t, mustCreateECDSAKey(t, instance, alg))
}

func mustCreateSerializedPublicKey(t *testing.T, instance mldsapb.MlDsaInstance, classicalAlg compositemldsapb.CompositeMlDsaClassicalAlgorithm, mldsaPubKeyBytes, classicalPubKeyBytes []byte, classicalTypeURL string) []byte {
	t.Helper()
	protoKey := &compositemldsapb.CompositeMlDsaPublicKey{
		Version: publicKeyProtoVersion,
		Params: &compositemldsapb.CompositeMlDsaParams{
			MlDsaInstance:      instance,
			ClassicalAlgorithm: classicalAlg,
		},
		MlDsaPublicKey: &tinkpb.KeyData{
			TypeUrl:         "type.googleapis.com/google.crypto.tink.MlDsaPublicKey",
			Value:           mldsaPubKeyBytes,
			KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
		},
		ClassicalPublicKey: &tinkpb.KeyData{
			TypeUrl:         classicalTypeURL,
			Value:           classicalPubKeyBytes,
			KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
		},
	}
	return mustMarshal(t, protoKey)
}

func mustCreateCompositePublicKey(t *testing.T, mldsaPubKey *mldsa.PublicKey, classicalPubKey key.Key, idRequirement uint32, params *Parameters) *PublicKey {
	t.Helper()
	pubKey, err := NewPublicKey(mldsaPubKey, classicalPubKey, idRequirement, params)
	if err != nil {
		t.Fatalf("NewPublicKey err = %v", err)
	}
	return pubKey
}

func protoInstanceEnum(instance MLDSAInstance) mldsapb.MlDsaInstance {
	switch instance {
	case MLDSA65:
		return mldsapb.MlDsaInstance_ML_DSA_65
	case MLDSA87:
		return mldsapb.MlDsaInstance_ML_DSA_87
	default:
		return mldsapb.MlDsaInstance_ML_DSA_UNKNOWN_INSTANCE
	}
}

func protoClassicalEnum(alg ClassicalAlgorithm) compositemldsapb.CompositeMlDsaClassicalAlgorithm {
	switch alg {
	case Ed25519:
		return compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_ED25519
	case ECDSAP256:
		return compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_ECDSA_P256
	case ECDSAP384:
		return compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_ECDSA_P384
	case ECDSAP521:
		return compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_ECDSA_P521
	case RSA3072PSS:
		return compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_RSA3072_PSS
	case RSA4096PSS:
		return compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_RSA4096_PSS
	case RSA3072PKCS1:
		return compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_RSA3072_PKCS1
	case RSA4096PKCS1:
		return compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_RSA4096_PKCS1
	default:
		return compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_UNKNOWN
	}
}

func TestParsePublicKey(t *testing.T) {
	for _, tc := range compmldsatestvectors.TestCasesSupportedParameters(t) {
		instance := MLDSAInstance(tc.Instance)
		classicalAlg := ClassicalAlgorithm(tc.ClassicalAlgorithm)
		variant := Variant(tc.Variant)

		testName := fmt.Sprintf("%v-%v-%v", instance, classicalAlg, variant)
		t.Run(testName, func(t *testing.T) {
			mlDsaPubKey, classicalPubKey := compmldsatestvectors.CreatePublicKeyDeterministic(t, compmldsainternal.MLDSAInstance(instance), compmldsainternal.ClassicalAlgorithm(classicalAlg))
			if mlDsaPubKey == nil || classicalPubKey == nil {
				t.Fatalf("failed to get deterministic keys")
			}

			mlDsaKeyVal := mustSerializeKey(t, mlDsaPubKey)
			classicalKeyVal := mustSerializeKey(t, classicalPubKey)

			typeURL, err := typeURLForClassicalAlgorithm(classicalAlg, false)
			if err != nil {
				t.Fatalf("typeURLForClassicalAlgorithm err = %v", err)
			}

			val := mustCreateSerializedPublicKey(t,
				protoInstanceEnum(instance),
				protoClassicalEnum(classicalAlg),
				mlDsaKeyVal,
				classicalKeyVal,
				typeURL,
			)

			var keyID uint32
			var prefixType tinkpb.OutputPrefixType = tinkpb.OutputPrefixType_RAW
			if variant == VariantTink {
				prefixType = tinkpb.OutputPrefixType_TINK
				keyID = 12345
			}

			keySerialization := mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           val,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, prefixType, keyID)

			wantKey := mustCreateCompositePublicKey(t,
				mlDsaPubKey,
				classicalPubKey,
				keyID,
				&Parameters{mlDSAInstance: instance, classicalAlgorithm: classicalAlg, variant: variant},
			)

			parser := &publicKeyParser{}
			gotKey, err := parser.ParseKey(keySerialization)
			if err != nil {
				t.Fatalf("parser.ParseKey(%v) err = %v", keySerialization, err)
			}
			if !gotKey.Equal(wantKey) {
				t.Errorf("gotKey.Equal(wantKey) = false, want true")
			}
		})
	}
}

func TestSerializePublicKey(t *testing.T) {
	for _, tc := range compmldsatestvectors.TestCasesSupportedParameters(t) {
		instance := MLDSAInstance(tc.Instance)
		classicalAlg := ClassicalAlgorithm(tc.ClassicalAlgorithm)
		variant := Variant(tc.Variant)

		testName := fmt.Sprintf("%v-%v-%v", instance, classicalAlg, variant)
		t.Run(testName, func(t *testing.T) {
			mlDsaPubKey, classicalPubKey := compmldsatestvectors.CreatePublicKeyDeterministic(t, compmldsainternal.MLDSAInstance(instance), compmldsainternal.ClassicalAlgorithm(classicalAlg))
			if mlDsaPubKey == nil || classicalPubKey == nil {
				t.Fatalf("failed to get deterministic keys")
			}

			mlDsaKeyVal := mustSerializeKey(t, mlDsaPubKey)
			classicalKeyVal := mustSerializeKey(t, classicalPubKey)

			typeURL, err := typeURLForClassicalAlgorithm(classicalAlg, false)
			if err != nil {
				t.Fatalf("typeURLForClassicalAlgorithm err = %v", err)
			}

			val := mustCreateSerializedPublicKey(t,
				protoInstanceEnum(instance),
				protoClassicalEnum(classicalAlg),
				mlDsaKeyVal,
				classicalKeyVal,
				typeURL,
			)

			var keyID uint32
			var prefixType tinkpb.OutputPrefixType = tinkpb.OutputPrefixType_RAW
			if variant == VariantTink {
				prefixType = tinkpb.OutputPrefixType_TINK
				keyID = 12345
			}

			keySerialization := mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           val,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, prefixType, keyID)

			keyInput := mustCreateCompositePublicKey(t,
				mlDsaPubKey,
				classicalPubKey,
				keyID,
				&Parameters{mlDSAInstance: instance, classicalAlgorithm: classicalAlg, variant: variant},
			)

			serializer := &publicKeySerializer{}
			gotSerialization, err := serializer.SerializeKey(keyInput)
			if err != nil {
				t.Fatalf("serializer.SerializeKey(keyInput) err = %v", err)
			}
			if !gotSerialization.Equal(keySerialization) {
				t.Errorf("gotSerialization.Equal(keySerialization) = false, want true")
			}
		})
	}
}

type stubKey struct{}

func (k *stubKey) Parameters() key.Parameters    { return nil }
func (k *stubKey) Equal(other key.Key) bool      { return false }
func (k *stubKey) IDRequirement() (uint32, bool) { return 0, false }

func TestSerializePublicKeyFails(t *testing.T) {
	mldsaPubKey := mustCreateMLDSAKey(t, MLDSA65, ECDSAP256)
	ecdsaPubKey := mustCreateECDSAKey(t, MLDSA65, ECDSAP256)
	params, _ := NewParameters(ECDSAP256, MLDSA65, VariantTink)

	for _, tc := range []struct {
		name      string
		publicKey key.Key
	}{
		{
			name:      "nil_key",
			publicKey: nil,
		},
		{
			name:      "wrong_key_type",
			publicKey: &stubKey{},
		},
		{
			name:      "parameters_are_nil",
			publicKey: &PublicKey{mlDSAPublicKey: mldsaPubKey, classicalPublicKey: ecdsaPubKey},
		},
		{
			name:      "classical_public_key_is_nil",
			publicKey: &PublicKey{params: params, mlDSAPublicKey: mldsaPubKey, classicalPublicKey: nil},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &publicKeySerializer{}
			if _, err := s.SerializeKey(tc.publicKey); err == nil {
				t.Errorf("s.SerializeKey(%v) err = nil, want error", tc.publicKey)
			}
		})
	}
}

func TestParsePublicKeyFails(t *testing.T) {
	mldsa65Pub := mustSerializeKey(t, mustCreateMLDSAKey(t, MLDSA65, ECDSAP256))
	ecdsaP256 := mustSerializeKey(t, mustCreateECDSAKey(t, MLDSA65, ECDSAP256))
	ecdsaTypeURL := "type.googleapis.com/google.crypto.tink.EcdsaPublicKey"
	validValue := mustCreateSerializedPublicKey(t, mldsapb.MlDsaInstance_ML_DSA_65, compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_ECDSA_P256, mldsa65Pub, ecdsaP256, ecdsaTypeURL)

	// Create a proto with unsupported version
	protoKey := new(compositemldsapb.CompositeMlDsaPublicKey)
	proto.Unmarshal(validValue, protoKey)
	protoKey.Version = 1
	invalidVersionValue, _ := proto.Marshal(protoKey)

	// Create a proto with unknown instance
	protoKey = new(compositemldsapb.CompositeMlDsaPublicKey)
	proto.Unmarshal(validValue, protoKey)
	protoKey.Params.MlDsaInstance = mldsapb.MlDsaInstance_ML_DSA_UNKNOWN_INSTANCE
	unknownInstanceValue, _ := proto.Marshal(protoKey)

	// Create a proto with unknown classical algorithm
	protoKey = new(compositemldsapb.CompositeMlDsaPublicKey)
	proto.Unmarshal(validValue, protoKey)
	protoKey.Params.ClassicalAlgorithm = compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_UNKNOWN
	unknownClassicalValue, _ := proto.Marshal(protoKey)

	for _, tc := range []struct {
		name             string
		keySerialization *protoserialization.KeySerialization
	}{
		{
			name:             "key_serialization_is_nil",
			keySerialization: nil,
		},
		{
			name: "wrong_type_URL",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "wrong.type.url",
				Value:           validValue,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong_key_material_type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           validValue,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "invalid_proto",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           []byte("invalid proto"),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "unsupported_version",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           invalidVersionValue,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "unsupported_output_prefix_type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           validValue,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_LEGACY, 12345),
		},
		{
			name: "unknown_instance",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           unknownInstanceValue,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "unknown_classical_algorithm",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           unknownClassicalValue,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &publicKeyParser{}
			if _, err := p.ParseKey(tc.keySerialization); err == nil {
				t.Errorf("p.ParseKey(%v) err = nil, want error", tc.keySerialization)
			}
		})
	}
}
