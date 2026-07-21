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

package jwtmldsa

import (
	"bytes"
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"

	jwtmldsapb "github.com/tink-crypto/tink-go/v2/proto/jwt_ml_dsa_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	privateKeyTypeURL = "type.googleapis.com/google.crypto.tink.JwtMlDsaPrivateKey"
	publicKeyTypeURL  = "type.googleapis.com/google.crypto.tink.JwtMlDsaPublicKey"
)

type parametersSerializer struct{}

var _ protoserialization.ParametersSerializer = (*parametersSerializer)(nil)

func algorithmToProto(a Algorithm) jwtmldsapb.JwtMlDsaAlgorithm {
	switch a {
	case MLDSA44:
		return jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA44
	case MLDSA65:
		return jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA65
	case MLDSA87:
		return jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA87
	}
	return jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA_UNKNOWN
}

func algorithmFromProto(a jwtmldsapb.JwtMlDsaAlgorithm) Algorithm {
	switch a {
	case jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA44:
		return MLDSA44
	case jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA65:
		return MLDSA65
	case jwtmldsapb.JwtMlDsaAlgorithm_ML_DSA87:
		return MLDSA87
	}
	return UnknownAlgorithm
}

func outputPrefixTypeFromKIDStrategy(s KIDStrategy) tinkpb.OutputPrefixType {
	switch s {
	case CustomKID:
		return tinkpb.OutputPrefixType_RAW
	case IgnoredKID:
		return tinkpb.OutputPrefixType_RAW
	case Base64EncodedKeyIDAsKID:
		return tinkpb.OutputPrefixType_TINK
	}
	return tinkpb.OutputPrefixType_UNKNOWN_PREFIX
}

func kidStrategyFromOutputPrefixType(s tinkpb.OutputPrefixType, hasCustomKID bool) KIDStrategy {
	switch s {
	case tinkpb.OutputPrefixType_RAW:
		if hasCustomKID {
			return CustomKID
		}
		return IgnoredKID
	case tinkpb.OutputPrefixType_TINK:
		return Base64EncodedKeyIDAsKID
	}
	return UnknownKIDStrategy
}

func (s *parametersSerializer) Serialize(p key.Parameters) (*tinkpb.KeyTemplate, error) {
	if p == nil {
		return nil, fmt.Errorf("jwtmldsa: parameters can't be nil")
	}
	params, ok := p.(*Parameters)
	if !ok {
		return nil, fmt.Errorf("jwtmldsa: invalid parameters type: got %T, want %T", p, (*Parameters)(nil))
	}
	keyFormat := &jwtmldsapb.JwtMlDsaKeyFormat{
		Algorithm: algorithmToProto(params.Algorithm()),
		Version:   0,
	}
	serializedKeyFormat, err := proto.Marshal(keyFormat)
	if err != nil {
		return nil, fmt.Errorf("jwtmldsa: failed to marshal JwtMlDsaKeyFormat: %v", err)
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          privateKeyTypeURL,
		Value:            serializedKeyFormat,
		OutputPrefixType: outputPrefixTypeFromKIDStrategy(params.kidStrategy),
	}, nil
}

type parametersParser struct{}

var _ protoserialization.ParametersParser = (*parametersParser)(nil)

func (s *parametersParser) Parse(kt *tinkpb.KeyTemplate) (key.Parameters, error) {
	if kt == nil {
		return nil, fmt.Errorf("jwtmldsa: key template can't be nil")
	}
	if kt.GetTypeUrl() != privateKeyTypeURL {
		return nil, fmt.Errorf("jwtmldsa: invalid type URL: got %q, want %q", kt.GetTypeUrl(), privateKeyTypeURL)
	}
	keyFormat := &jwtmldsapb.JwtMlDsaKeyFormat{}
	if err := proto.Unmarshal(kt.GetValue(), keyFormat); err != nil {
		return nil, fmt.Errorf("jwtmldsa: failed to unmarshal JwtMlDsaKeyFormat: %v", err)
	}
	if keyFormat.GetVersion() != 0 {
		return nil, fmt.Errorf("jwtmldsa: invalid version: got %d, want 0", keyFormat.GetVersion())
	}
	kidStrategy := kidStrategyFromOutputPrefixType(kt.GetOutputPrefixType(), false)
	return NewParameters(kidStrategy, algorithmFromProto(keyFormat.GetAlgorithm()))
}

func publicKeyToProto(k *PublicKey) (*jwtmldsapb.JwtMlDsaPublicKey, error) {
	protoPublicKey := &jwtmldsapb.JwtMlDsaPublicKey{
		Version:   0,
		Algorithm: algorithmToProto(k.parameters.Algorithm()),
		KeyValue:  bytes.Clone(k.keyBytes),
	}
	if k.parameters.KIDStrategy() == CustomKID {
		protoPublicKey.CustomKid = &jwtmldsapb.JwtMlDsaPublicKey_CustomKid{
			Value: k.kid,
		}
	}
	return protoPublicKey, nil
}

type publicKeySerializer struct{}

var _ protoserialization.KeySerializer = (*publicKeySerializer)(nil)

func (s *publicKeySerializer) SerializeKey(k key.Key) (*protoserialization.KeySerialization, error) {
	jwtMLDSAPublicKey, ok := k.(*PublicKey)
	if !ok {
		return nil, fmt.Errorf("jwtmldsa: key is of type %T; needed *PublicKey", k)
	}
	protoPublicKey, err := publicKeyToProto(jwtMLDSAPublicKey)
	if err != nil {
		return nil, err
	}
	serializedPublicKey, err := proto.Marshal(protoPublicKey)
	if err != nil {
		return nil, fmt.Errorf("jwtmldsa: failed to marshal JwtMlDsaPublicKey: %v", err)
	}

	idRequirement, _ := jwtMLDSAPublicKey.IDRequirement()
	return protoserialization.NewKeySerialization(&tinkpb.KeyData{
		TypeUrl:         publicKeyTypeURL,
		Value:           serializedPublicKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, outputPrefixTypeFromKIDStrategy(jwtMLDSAPublicKey.parameters.KIDStrategy()), idRequirement)
}

func publicKeyFromProto(protoPublicKey *jwtmldsapb.JwtMlDsaPublicKey, keySerialization *protoserialization.KeySerialization) (*PublicKey, error) {
	if protoPublicKey.GetVersion() != 0 {
		return nil, fmt.Errorf("jwtmldsa: invalid public key version: got %d, want 0", protoPublicKey.GetVersion())
	}
	kidStrategy := kidStrategyFromOutputPrefixType(keySerialization.OutputPrefixType(), protoPublicKey.GetCustomKid() != nil)
	params, err := NewParameters(kidStrategy, algorithmFromProto(protoPublicKey.GetAlgorithm()))
	if err != nil {
		return nil, err
	}
	keyID, _ := keySerialization.IDRequirement()
	return NewPublicKey(PublicKeyOpts{
		KeyBytes:      protoPublicKey.GetKeyValue(),
		IDRequirement: keyID,
		HasCustomKID:  protoPublicKey.GetCustomKid() != nil,
		CustomKID:     protoPublicKey.GetCustomKid().GetValue(),
		Parameters:    params,
	})
}

type publicKeyParser struct{}

var _ protoserialization.KeyParser = (*publicKeyParser)(nil)

func (s *publicKeyParser) ParseKey(keySerialization *protoserialization.KeySerialization) (key.Key, error) {
	if keySerialization == nil {
		return nil, fmt.Errorf("jwtmldsa: key serialization can't be nil")
	}
	if keySerialization.KeyData().GetTypeUrl() != publicKeyTypeURL {
		return nil, fmt.Errorf("jwtmldsa: invalid type URL: got %q, want %q", keySerialization.KeyData().GetTypeUrl(), publicKeyTypeURL)
	}
	if keySerialization.KeyData().GetKeyMaterialType() != tinkpb.KeyData_ASYMMETRIC_PUBLIC {
		return nil, fmt.Errorf("jwtmldsa: invalid key material type: got %v, want %v", keySerialization.KeyData().GetKeyMaterialType(), tinkpb.KeyData_ASYMMETRIC_PUBLIC)
	}

	publicKeyProto := &jwtmldsapb.JwtMlDsaPublicKey{}
	if err := proto.Unmarshal(keySerialization.KeyData().GetValue(), publicKeyProto); err != nil {
		return nil, fmt.Errorf("jwtmldsa: failed to unmarshal JwtMlDsaPublicKey: %v", err)
	}
	return publicKeyFromProto(publicKeyProto, keySerialization)
}

type privateKeySerializer struct{}

var _ protoserialization.KeySerializer = (*privateKeySerializer)(nil)

func (s *privateKeySerializer) SerializeKey(k key.Key) (*protoserialization.KeySerialization, error) {
	jwtMLDSAPrivateKey, ok := k.(*PrivateKey)
	if !ok {
		return nil, fmt.Errorf("jwtmldsa: key is of type %T; needed *PrivateKey", k)
	}
	publicKey, err := jwtMLDSAPrivateKey.PublicKey()
	if err != nil {
		return nil, err
	}
	jwtMLDSAPublicKey, ok := publicKey.(*PublicKey)
	if !ok {
		return nil, fmt.Errorf("jwtmldsa: public key is of type %T; needed *PublicKey", publicKey)
	}
	protoPublicKey, err := publicKeyToProto(jwtMLDSAPublicKey)
	if err != nil {
		return nil, err
	}
	protoPrivateKey := &jwtmldsapb.JwtMlDsaPrivateKey{
		Version:   0,
		PublicKey: protoPublicKey,
		KeyValue:  jwtMLDSAPrivateKey.privateKeyBytes.Data(insecuresecretdataaccess.Token{}),
	}
	serializedPrivateKey, err := proto.Marshal(protoPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("jwtmldsa: failed to marshal JwtMlDsaPrivateKey: %v", err)
	}
	idRequirement, _ := jwtMLDSAPrivateKey.IDRequirement()
	return protoserialization.NewKeySerialization(&tinkpb.KeyData{
		TypeUrl:         privateKeyTypeURL,
		Value:           serializedPrivateKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, outputPrefixTypeFromKIDStrategy(jwtMLDSAPublicKey.parameters.KIDStrategy()), idRequirement)
}

type privateKeyParser struct{}

var _ protoserialization.KeyParser = (*privateKeyParser)(nil)

func (s *privateKeyParser) ParseKey(keySerialization *protoserialization.KeySerialization) (key.Key, error) {
	if keySerialization == nil {
		return nil, fmt.Errorf("jwtmldsa: key serialization can't be nil")
	}
	if keySerialization.KeyData().GetTypeUrl() != privateKeyTypeURL {
		return nil, fmt.Errorf("jwtmldsa: invalid type URL: got %q, want %q", keySerialization.KeyData().GetTypeUrl(), privateKeyTypeURL)
	}
	if keySerialization.KeyData().GetKeyMaterialType() != tinkpb.KeyData_ASYMMETRIC_PRIVATE {
		return nil, fmt.Errorf("jwtmldsa: invalid key material type: got %v, want %v", keySerialization.KeyData().GetKeyMaterialType(), tinkpb.KeyData_ASYMMETRIC_PRIVATE)
	}
	privateKeyProto := &jwtmldsapb.JwtMlDsaPrivateKey{}
	if err := proto.Unmarshal(keySerialization.KeyData().GetValue(), privateKeyProto); err != nil {
		return nil, fmt.Errorf("jwtmldsa: failed to unmarshal JwtMlDsaPrivateKey: %v", err)
	}
	if privateKeyProto.GetVersion() != 0 {
		return nil, fmt.Errorf("jwtmldsa: invalid version: got %d, want 0", privateKeyProto.GetVersion())
	}
	publicKey, err := publicKeyFromProto(privateKeyProto.GetPublicKey(), keySerialization)
	if err != nil {
		return nil, err
	}
	return NewPrivateKeyFromPublicKey(
		secretdata.NewBytesFromData(privateKeyProto.GetKeyValue(), insecuresecretdataaccess.Token{}),
		publicKey,
	)
}
