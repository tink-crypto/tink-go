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

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/signature/ecdsa"
	"github.com/tink-crypto/tink-go/v2/signature/ed25519"
	"github.com/tink-crypto/tink-go/v2/signature/mldsa"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapkcs1"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapss"
	mldsapb "github.com/tink-crypto/tink-go/v2/proto/ml_dsa_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"

	compositemldsapb "github.com/tink-crypto/tink-go/v2/proto/composite_ml_dsa_go_proto"
)

const (
	// publicKeyProtoVersion is the accepted [compositemldsapb.CompositeMlDsaPublicKey] proto
	// version.
	//
	// Currently, only version 0 is supported; other versions are rejected.
	publicKeyProtoVersion = 0

	verifierTypeURL = "type.googleapis.com/google.crypto.tink.CompositeMlDsaPublicKey"
)

type publicKeySerializer struct{}

var _ protoserialization.KeySerializer = (*publicKeySerializer)(nil)

func protoOutputPrefixTypeFromVariant(variant Variant) (tinkpb.OutputPrefixType, error) {
	switch variant {
	case VariantTink:
		return tinkpb.OutputPrefixType_TINK, nil
	case VariantNoPrefix:
		return tinkpb.OutputPrefixType_RAW, nil
	default:
		return tinkpb.OutputPrefixType_UNKNOWN_PREFIX, fmt.Errorf("unknown output prefix variant: %v", variant)
	}
}

func protoMlDsaInstanceFromInstance(instance MLDSAInstance) (mldsapb.MlDsaInstance, error) {
	switch instance {
	case MLDSA65:
		return mldsapb.MlDsaInstance_ML_DSA_65, nil
	case MLDSA87:
		return mldsapb.MlDsaInstance_ML_DSA_87, nil
	default:
		return mldsapb.MlDsaInstance_ML_DSA_UNKNOWN_INSTANCE, fmt.Errorf("unknown instance: %v", instance)
	}
}

func protoCompositeMlDsaClassicalAlgorithmFromCompositeMlDsaClassicalAlgorithm(alg ClassicalAlgorithm) (compositemldsapb.CompositeMlDsaClassicalAlgorithm, error) {
	switch alg {
	case Ed25519:
		return compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_ED25519, nil
	case ECDSAP256:
		return compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_ECDSA_P256, nil
	case ECDSAP384:
		return compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_ECDSA_P384, nil
	case ECDSAP521:
		return compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_ECDSA_P521, nil
	case RSA3072PSS:
		return compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_RSA3072_PSS, nil
	case RSA4096PSS:
		return compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_RSA4096_PSS, nil
	case RSA3072PKCS1:
		return compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_RSA3072_PKCS1, nil
	case RSA4096PKCS1:
		return compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_RSA4096_PKCS1, nil
	default:
		return compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_UNKNOWN, fmt.Errorf("unknown classical algorithm: %v", alg)
	}
}

func typeURLForClassicalAlgorithm(alg ClassicalAlgorithm, private bool) (string, error) {
	switch alg {
	case Ed25519:
		if private {
			return "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey", nil
		}
		return "type.googleapis.com/google.crypto.tink.Ed25519PublicKey", nil
	case ECDSAP256, ECDSAP384, ECDSAP521:
		if private {
			return "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey", nil
		}
		return "type.googleapis.com/google.crypto.tink.EcdsaPublicKey", nil
	case RSA3072PSS, RSA4096PSS:
		if private {
			return "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey", nil
		}
		return "type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey", nil
	case RSA3072PKCS1, RSA4096PKCS1:
		if private {
			return "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey", nil
		}
		return "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey", nil
	default:
		return "", fmt.Errorf("unknown classical algorithm: %v", alg)
	}
}

func serializeClassicalKey(k key.Key) ([]byte, error) {
	switch k.(type) {
	case *ed25519.PublicKey, *ecdsa.PublicKey, *rsassapss.PublicKey, *rsassapkcs1.PublicKey, *ed25519.PrivateKey, *ecdsa.PrivateKey, *rsassapss.PrivateKey, *rsassapkcs1.PrivateKey:
		serialization, err := protoserialization.SerializeKey(k)
		if err != nil {
			return nil, err
		}
		return serialization.KeyData().GetValue(), nil
	default:
		return nil, fmt.Errorf("unsupported classical key type: %T", k)
	}
}

func (s *publicKeySerializer) SerializeKey(k key.Key) (*protoserialization.KeySerialization, error) {
	compPubKey, ok := k.(*PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid key type: %T, want *compositemldsa.PublicKey", k)
	}
	if compPubKey.params == nil {
		return nil, fmt.Errorf("invalid key: parameters are nil")
	}
	outputPrefixType, err := protoOutputPrefixTypeFromVariant(compPubKey.params.Variant())
	if err != nil {
		return nil, err
	}
	mldsaInstance, err := protoMlDsaInstanceFromInstance(compPubKey.params.MLDSAInstance())
	if err != nil {
		return nil, err
	}
	classicalAlgorithm, err := protoCompositeMlDsaClassicalAlgorithmFromCompositeMlDsaClassicalAlgorithm(compPubKey.params.ClassicalAlgorithm())
	if err != nil {
		return nil, err
	}

	classicalTypeURL, err := typeURLForClassicalAlgorithm(compPubKey.params.ClassicalAlgorithm(), false)
	if err != nil {
		return nil, err
	}

	classicalPubKeyBytes, err := serializeClassicalKey(compPubKey.classicalPublicKey)
	if err != nil {
		return nil, err
	}
	classicalPubKeyData := &tinkpb.KeyData{
		TypeUrl:         classicalTypeURL,
		Value:           classicalPubKeyBytes,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}

	mldsaPubKeySerialization, err := protoserialization.SerializeKey(compPubKey.mlDSAPublicKey)
	if err != nil {
		return nil, err
	}
	mldsaPubKeyData := mldsaPubKeySerialization.KeyData()

	protoKey := &compositemldsapb.CompositeMlDsaPublicKey{
		Version: publicKeyProtoVersion,
		Params: &compositemldsapb.CompositeMlDsaParams{
			MlDsaInstance:      mldsaInstance,
			ClassicalAlgorithm: classicalAlgorithm,
		},
		MlDsaPublicKey:     mldsaPubKeyData,
		ClassicalPublicKey: classicalPubKeyData,
	}
	serializedKey, err := proto.Marshal(protoKey)
	if err != nil {
		return nil, err
	}
	idRequirement, _ := compPubKey.IDRequirement()
	keyData := &tinkpb.KeyData{
		TypeUrl:         verifierTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}
	return protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
}

type publicKeyParser struct{}

var _ protoserialization.KeyParser = (*publicKeyParser)(nil)

func variantFromProto(prefixType tinkpb.OutputPrefixType) (Variant, error) {
	switch prefixType {
	case tinkpb.OutputPrefixType_TINK:
		return VariantTink, nil
	case tinkpb.OutputPrefixType_RAW:
		return VariantNoPrefix, nil
	default:
		return VariantUnknown, fmt.Errorf("unsupported output prefix type: %v", prefixType)
	}
}

func instanceFromProto(instanceType mldsapb.MlDsaInstance) (MLDSAInstance, error) {
	switch instanceType {
	case mldsapb.MlDsaInstance_ML_DSA_65:
		return MLDSA65, nil
	case mldsapb.MlDsaInstance_ML_DSA_87:
		return MLDSA87, nil
	default:
		return UnknownInstance, fmt.Errorf("unsupported instance type: %v", instanceType)
	}
}

func classicalAlgorithmFromProto(algType compositemldsapb.CompositeMlDsaClassicalAlgorithm) (ClassicalAlgorithm, error) {
	switch algType {
	case compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_ED25519:
		return Ed25519, nil
	case compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_ECDSA_P256:
		return ECDSAP256, nil
	case compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_ECDSA_P384:
		return ECDSAP384, nil
	case compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_ECDSA_P521:
		return ECDSAP521, nil
	case compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_RSA3072_PSS:
		return RSA3072PSS, nil
	case compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_RSA4096_PSS:
		return RSA4096PSS, nil
	case compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_RSA3072_PKCS1:
		return RSA3072PKCS1, nil
	case compositemldsapb.CompositeMlDsaClassicalAlgorithm_CLASSICAL_ALGORITHM_RSA4096_PKCS1:
		return RSA4096PKCS1, nil
	default:
		return UnknownAlgorithm, fmt.Errorf("unsupported classical algorithm type: %v", algType)
	}
}

func parseClassicalPublicKey(classicalPubKeyData *tinkpb.KeyData) (key.Key, error) {
	if classicalPubKeyData == nil {
		return nil, fmt.Errorf("classical public key data is nil")
	}
	// Classical keys are stored with RAW prefix type within the composite key.
	serialization, err := protoserialization.NewKeySerialization(classicalPubKeyData, tinkpb.OutputPrefixType_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create key serialization for classical public key: %v", err)
	}
	parsedKey, err := protoserialization.ParseKey(serialization)
	if err != nil {
		return nil, fmt.Errorf("failed to parse classical public key: %v", err)
	}
	return parsedKey, nil
}

func parseMLDSAPublicKey(mldsaPubKeyData *tinkpb.KeyData) (*mldsa.PublicKey, error) {
	if mldsaPubKeyData == nil {
		return nil, fmt.Errorf("ml-dsa public key data is nil")
	}
	// The embedded ML-DSA key has no prefix.
	mldsaKeySerialization, err := protoserialization.NewKeySerialization(mldsaPubKeyData, tinkpb.OutputPrefixType_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create key serialization for ML-DSA public key: %v", err)
	}
	parsedMLDSAKey, err := protoserialization.ParseKey(mldsaKeySerialization)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ML-DSA public key: %v", err)
	}
	mldsaPubKey, ok := parsedMLDSAKey.(*mldsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("parsed ML-DSA key is not a PublicKey")
	}
	return mldsaPubKey, nil
}

func (s *publicKeyParser) ParseKey(keySerialization *protoserialization.KeySerialization) (key.Key, error) {
	if keySerialization == nil {
		return nil, fmt.Errorf("key serialization is nil")
	}
	keyData := keySerialization.KeyData()
	if keyData.GetTypeUrl() != verifierTypeURL {
		return nil, fmt.Errorf("invalid key type URL: %v", keyData.GetTypeUrl())
	}
	if keyData.GetKeyMaterialType() != tinkpb.KeyData_ASYMMETRIC_PUBLIC {
		return nil, fmt.Errorf("invalid key material type: %v", keyData.GetKeyMaterialType())
	}
	protoKey := new(compositemldsapb.CompositeMlDsaPublicKey)
	if err := proto.Unmarshal(keyData.GetValue(), protoKey); err != nil {
		return nil, err
	}
	if protoKey.GetVersion() != publicKeyProtoVersion {
		return nil, fmt.Errorf("public key has unsupported version: %v", protoKey.GetVersion())
	}
	variant, err := variantFromProto(keySerialization.OutputPrefixType())
	if err != nil {
		return nil, err
	}
	instance, err := instanceFromProto(protoKey.GetParams().GetMlDsaInstance())
	if err != nil {
		return nil, err
	}
	classicalAlgorithm, err := classicalAlgorithmFromProto(protoKey.GetParams().GetClassicalAlgorithm())
	if err != nil {
		return nil, err
	}
	params, err := NewParameters(classicalAlgorithm, instance, variant)
	if err != nil {
		return nil, err
	}
	keyID, _ := keySerialization.IDRequirement()

	mldsaPubKey, err := parseMLDSAPublicKey(protoKey.GetMlDsaPublicKey())
	if err != nil {
		return nil, err
	}

	classicalPubKey, err := parseClassicalPublicKey(protoKey.GetClassicalPublicKey())
	if err != nil {
		return nil, err
	}

	return NewPublicKey(mldsaPubKey, classicalPubKey, keyID, params)
}
