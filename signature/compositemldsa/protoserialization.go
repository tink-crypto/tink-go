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
	// privateKeyProtoVersion is the accepted [cmdpb.CompositeMlDsaPrivateKey] proto
	// version.
	//
	// Currently, only version 0 is supported; other versions are rejected.
	privateKeyProtoVersion = 0

	signerTypeURL   = "type.googleapis.com/google.crypto.tink.CompositeMlDsaPrivateKey"
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

func typeURLForClassicalAlgorithm(algorithm ClassicalAlgorithm, private bool) (string, error) {
	switch algorithm {
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
		return "", fmt.Errorf("unknown classical algorithm: %v", algorithm)
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
	compositePublicKey, ok := k.(*PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid key type: %T, want *compositemldsa.PublicKey", k)
	}
	if compositePublicKey.params == nil {
		return nil, fmt.Errorf("invalid key: parameters are nil")
	}
	outputPrefixType, err := protoOutputPrefixTypeFromVariant(compositePublicKey.params.Variant())
	if err != nil {
		return nil, err
	}
	mldsaInstance, err := protoMlDsaInstanceFromInstance(compositePublicKey.params.MLDSAInstance())
	if err != nil {
		return nil, err
	}
	classicalAlgorithm, err := protoCompositeMlDsaClassicalAlgorithmFromCompositeMlDsaClassicalAlgorithm(compositePublicKey.params.ClassicalAlgorithm())
	if err != nil {
		return nil, err
	}

	classicalTypeURL, err := typeURLForClassicalAlgorithm(compositePublicKey.params.ClassicalAlgorithm(), false)
	if err != nil {
		return nil, err
	}

	classicalPublicKeyBytes, err := serializeClassicalKey(compositePublicKey.classicalPublicKey)
	if err != nil {
		return nil, err
	}
	classicalPublicKeyData := &tinkpb.KeyData{
		TypeUrl:         classicalTypeURL,
		Value:           classicalPublicKeyBytes,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}

	mldsaPublicKeySerialization, err := protoserialization.SerializeKey(compositePublicKey.mlDSAPublicKey)
	if err != nil {
		return nil, err
	}
	mldsaPublicKeyData := mldsaPublicKeySerialization.KeyData()

	protoKey := &compositemldsapb.CompositeMlDsaPublicKey{
		Version: publicKeyProtoVersion,
		Params: &compositemldsapb.CompositeMlDsaParams{
			MlDsaInstance:      mldsaInstance,
			ClassicalAlgorithm: classicalAlgorithm,
		},
		MlDsaPublicKey:     mldsaPublicKeyData,
		ClassicalPublicKey: classicalPublicKeyData,
	}
	serializedKey, err := proto.Marshal(protoKey)
	if err != nil {
		return nil, err
	}
	idRequirement, _ := compositePublicKey.IDRequirement()
	keyData := &tinkpb.KeyData{
		TypeUrl:         verifierTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}
	return protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
}

type privateKeySerializer struct{}

var _ protoserialization.KeySerializer = (*privateKeySerializer)(nil)

func (s *privateKeySerializer) SerializeKey(k key.Key) (*protoserialization.KeySerialization, error) {
	compositePrivateKey, ok := k.(*PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid key type: %T, want *compositemldsa.PrivateKey", k)
	}
	if compositePrivateKey.publicKey == nil {
		return nil, fmt.Errorf("invalid key: public key is nil")
	}
	params := compositePrivateKey.publicKey.params
	if params == nil {
		return nil, fmt.Errorf("invalid key: public key parameters are nil")
	}
	outputPrefixType, err := protoOutputPrefixTypeFromVariant(params.Variant())
	if err != nil {
		return nil, err
	}
	mldsaInstance, err := protoMlDsaInstanceFromInstance(params.MLDSAInstance())
	if err != nil {
		return nil, err
	}
	classicalAlgorithm, err := protoCompositeMlDsaClassicalAlgorithmFromCompositeMlDsaClassicalAlgorithm(params.ClassicalAlgorithm())
	if err != nil {
		return nil, err
	}

	classicalTypeURL, err := typeURLForClassicalAlgorithm(params.ClassicalAlgorithm(), true)
	if err != nil {
		return nil, err
	}
	classicalPrivateKeyBytes, err := serializeClassicalKey(compositePrivateKey.classicalPrivateKey)
	if err != nil {
		return nil, err
	}
	classicalPrivateKeyData := &tinkpb.KeyData{
		TypeUrl:         classicalTypeURL,
		Value:           classicalPrivateKeyBytes,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}

	mldsaPrivateKeySerialization, err := protoserialization.SerializeKey(compositePrivateKey.mlDSAPrivateKey)
	if err != nil {
		return nil, err
	}
	mldsaPrivateKeyData := mldsaPrivateKeySerialization.KeyData()

	protoKey := &compositemldsapb.CompositeMlDsaPrivateKey{
		Version: privateKeyProtoVersion,
		Params: &compositemldsapb.CompositeMlDsaParams{
			MlDsaInstance:      mldsaInstance,
			ClassicalAlgorithm: classicalAlgorithm,
		},
		MlDsaPrivateKey:     mldsaPrivateKeyData,
		ClassicalPrivateKey: classicalPrivateKeyData,
	}
	serializedKey, err := proto.Marshal(protoKey)
	if err != nil {
		return nil, err
	}
	idRequirement, _ := compositePrivateKey.IDRequirement()
	keyData := &tinkpb.KeyData{
		TypeUrl:         signerTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
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

func classicalAlgorithmFromProto(algorithmType compositemldsapb.CompositeMlDsaClassicalAlgorithm) (ClassicalAlgorithm, error) {
	switch algorithmType {
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
		return UnknownAlgorithm, fmt.Errorf("unsupported classical algorithm type: %v", algorithmType)
	}
}

func parseClassicalPublicKey(classicalPublicKeyData *tinkpb.KeyData) (key.Key, error) {
	if classicalPublicKeyData == nil {
		return nil, fmt.Errorf("classical public key data is nil")
	}
	// Classical keys are stored with RAW prefix type within the composite key.
	serialization, err := protoserialization.NewKeySerialization(classicalPublicKeyData, tinkpb.OutputPrefixType_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create key serialization for classical public key: %v", err)
	}
	parsedKey, err := protoserialization.ParseKey(serialization)
	if err != nil {
		return nil, fmt.Errorf("failed to parse classical public key: %v", err)
	}
	return parsedKey, nil
}

func parseMLDSAPublicKey(mldsaPublicKeyData *tinkpb.KeyData) (*mldsa.PublicKey, error) {
	if mldsaPublicKeyData == nil {
		return nil, fmt.Errorf("ml-dsa public key data is nil")
	}
	// The embedded ML-DSA key has no prefix.
	mldsaKeySerialization, err := protoserialization.NewKeySerialization(mldsaPublicKeyData, tinkpb.OutputPrefixType_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create key serialization for ML-DSA public key: %v", err)
	}
	parsedMLDSAKey, err := protoserialization.ParseKey(mldsaKeySerialization)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ML-DSA public key: %v", err)
	}
	mldsaPublicKey, ok := parsedMLDSAKey.(*mldsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("parsed ML-DSA key is not a PublicKey")
	}
	return mldsaPublicKey, nil
}

func parseClassicalPrivateKey(classicalPrivateKeyData *tinkpb.KeyData) (key.Key, error) {
	if classicalPrivateKeyData == nil {
		return nil, fmt.Errorf("classical private key data is nil")
	}
	// Classical keys are stored with RAW prefix type within the composite key.
	serialization, err := protoserialization.NewKeySerialization(classicalPrivateKeyData, tinkpb.OutputPrefixType_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("create key serialization for classical private key: %v", err)
	}
	parsedKey, err := protoserialization.ParseKey(serialization)
	if err != nil {
		return nil, fmt.Errorf("parse classical private key: %v", err)
	}
	return parsedKey, nil
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

	mldsaPublicKey, err := parseMLDSAPublicKey(protoKey.GetMlDsaPublicKey())
	if err != nil {
		return nil, err
	}

	classicalPublicKey, err := parseClassicalPublicKey(protoKey.GetClassicalPublicKey())
	if err != nil {
		return nil, err
	}

	return NewPublicKey(mldsaPublicKey, classicalPublicKey, keyID, params)
}

type privateKeyParser struct{}

var _ protoserialization.KeyParser = (*privateKeyParser)(nil)

func (s *privateKeyParser) ParseKey(keySerialization *protoserialization.KeySerialization) (key.Key, error) {
	if keySerialization == nil {
		return nil, fmt.Errorf("key serialization is nil")
	}
	keyData := keySerialization.KeyData()
	if keyData.GetTypeUrl() != signerTypeURL {
		return nil, fmt.Errorf("invalid key type URL: %v", keyData.GetTypeUrl())
	}
	if keyData.GetKeyMaterialType() != tinkpb.KeyData_ASYMMETRIC_PRIVATE {
		return nil, fmt.Errorf("invalid key material type: %v", keyData.GetKeyMaterialType())
	}
	protoKey := new(compositemldsapb.CompositeMlDsaPrivateKey)
	if err := proto.Unmarshal(keyData.GetValue(), protoKey); err != nil {
		return nil, err
	}
	if protoKey.GetVersion() != privateKeyProtoVersion {
		return nil, fmt.Errorf("private key has unsupported version: %v", protoKey.GetVersion())
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

	mldsaPrivateKeyData := protoKey.GetMlDsaPrivateKey()
	if mldsaPrivateKeyData == nil {
		return nil, fmt.Errorf("ml-dsa private key data is nil")
	}

	// The embedded ML-DSA key has no prefix.
	mldsaKeySerialization, err := protoserialization.NewKeySerialization(mldsaPrivateKeyData, tinkpb.OutputPrefixType_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("create key serialization for ML-DSA private key: %v", err)
	}

	parsedMLDSAKey, err := protoserialization.ParseKey(mldsaKeySerialization)
	if err != nil {
		return nil, fmt.Errorf("parse ML-DSA private key: %v", err)
	}
	mldsaPrivateKey, ok := parsedMLDSAKey.(*mldsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("parsed ML-DSA key is not a PrivateKey")
	}

	classicalPrivateKey, err := parseClassicalPrivateKey(protoKey.GetClassicalPrivateKey())
	if err != nil {
		return nil, err
	}

	return NewPrivateKey(mldsaPrivateKey, classicalPrivateKey, keyID, params)
}

type parametersSerializer struct{}

var _ protoserialization.ParametersSerializer = (*parametersSerializer)(nil)

func (s *parametersSerializer) Serialize(parameters key.Parameters) (*tinkpb.KeyTemplate, error) {
	compParams, ok := parameters.(*Parameters)
	if !ok {
		return nil, fmt.Errorf("invalid parameters type: got %T, want *compositemldsa.Parameters", parameters)
	}
	outputPrefixType, err := protoOutputPrefixTypeFromVariant(compParams.Variant())
	if err != nil {
		return nil, err
	}
	mldsaInstance, err := protoMlDsaInstanceFromInstance(compParams.MLDSAInstance())
	if err != nil {
		return nil, err
	}
	classicalAlgorithm, err := protoCompositeMlDsaClassicalAlgorithmFromCompositeMlDsaClassicalAlgorithm(compParams.ClassicalAlgorithm())
	if err != nil {
		return nil, err
	}
	format := &compositemldsapb.CompositeMlDsaKeyFormat{
		Params: &compositemldsapb.CompositeMlDsaParams{
			MlDsaInstance:      mldsaInstance,
			ClassicalAlgorithm: classicalAlgorithm,
		},
		Version: 0,
	}
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          signerTypeURL,
		OutputPrefixType: outputPrefixType,
		Value:            serializedFormat,
	}, nil
}

type parametersParser struct{}

var _ protoserialization.ParametersParser = (*parametersParser)(nil)

func (s *parametersParser) Parse(keyTemplate *tinkpb.KeyTemplate) (key.Parameters, error) {
	if keyTemplate.GetTypeUrl() != signerTypeURL {
		return nil, fmt.Errorf("invalid type URL: got %q, want %q", keyTemplate.GetTypeUrl(), signerTypeURL)
	}
	format := new(compositemldsapb.CompositeMlDsaKeyFormat)
	if err := proto.Unmarshal(keyTemplate.GetValue(), format); err != nil {
		return nil, err
	}
	if format.GetVersion() != 0 {
		return nil, fmt.Errorf("unsupported key version: got %d, want %d", format.GetVersion(), 0)
	}
	variant, err := variantFromProto(keyTemplate.GetOutputPrefixType())
	if err != nil {
		return nil, err
	}
	instance, err := instanceFromProto(format.GetParams().GetMlDsaInstance())
	if err != nil {
		return nil, err
	}
	classicalAlgorithm, err := classicalAlgorithmFromProto(format.GetParams().GetClassicalAlgorithm())
	if err != nil {
		return nil, err
	}
	params, err := NewParameters(classicalAlgorithm, instance, variant)
	if err != nil {
		return nil, err
	}
	return params, nil
}
