// Copyright 2024 Google LLC
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

package aesgcmsiv

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	gcmpb "github.com/tink-crypto/tink-go/v2/proto/aes_gcm_go_proto"
	aesgcmsivpb "github.com/tink-crypto/tink-go/v2/proto/aes_gcm_siv_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	// protoVersion is the accepted [gcmpb.AesGcmKey] proto version.
	//
	// Currently, only version 0 is supported; other versions are rejected.
	protoVersion = 0
	typeURL      = "type.googleapis.com/google.crypto.tink.AesGcmSivKey"
)

type keySerializer struct{}

var _ protoserialization.KeySerializer = (*keySerializer)(nil)

func protoOutputPrefixTypeFromVariant(variant Variant) (tinkpb.OutputPrefixType, error) {
	switch variant {
	case VariantTink:
		return tinkpb.OutputPrefixType_TINK, nil
	case VariantCrunchy:
		return tinkpb.OutputPrefixType_CRUNCHY, nil
	case VariantNoPrefix:
		return tinkpb.OutputPrefixType_RAW, nil
	default:
		return tinkpb.OutputPrefixType_UNKNOWN_PREFIX, fmt.Errorf("unknown output prefix variant: %v", variant)
	}
}

func (s *keySerializer) SerializeKey(key key.Key) (*protoserialization.KeySerialization, error) {
	actualKey, ok := key.(*Key)
	if !ok {
		return nil, fmt.Errorf("invalid key type: got %T, want *aesgcmsiv.Key", key)
	}
	outputPrefixType, err := protoOutputPrefixTypeFromVariant(actualKey.parameters.Variant())
	if err != nil {
		return nil, err
	}
	keyBytes := actualKey.KeyBytes()
	protoKey := &gcmpb.AesGcmKey{
		KeyValue: keyBytes.Data(insecuresecretdataaccess.Token{}),
		Version:  protoVersion,
	}
	serializedKey, err := proto.Marshal(protoKey)
	if err != nil {
		return nil, err
	}
	// idRequirement is zero if the key doesn't have a key requirement.
	idRequirement, _ := actualKey.IDRequirement()
	keyData := &tinkpb.KeyData{
		TypeUrl:         typeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}
	return protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
}

type keyParser struct{}

var _ protoserialization.KeyParser = (*keyParser)(nil)

func variantFromProto(prefixType tinkpb.OutputPrefixType) (Variant, error) {
	switch prefixType {
	case tinkpb.OutputPrefixType_TINK:
		return VariantTink, nil
	case tinkpb.OutputPrefixType_CRUNCHY, tinkpb.OutputPrefixType_LEGACY:
		return VariantCrunchy, nil
	case tinkpb.OutputPrefixType_RAW:
		return VariantNoPrefix, nil
	default:
		return VariantUnknown, fmt.Errorf("unsupported output prefix type: %v", prefixType)
	}
}

func (s *keyParser) ParseKey(keySerialization *protoserialization.KeySerialization) (key.Key, error) {
	if keySerialization == nil {
		return nil, fmt.Errorf("key serialization is nil")
	}
	keyData := keySerialization.KeyData()
	if keyData.GetTypeUrl() != typeURL {
		return nil, fmt.Errorf("invalid type URL: got %v, want %v", keyData.GetTypeUrl(), typeURL)
	}
	if keyData.GetKeyMaterialType() != tinkpb.KeyData_SYMMETRIC {
		return nil, fmt.Errorf("invalid key material type: got %v, want %v", keyData.GetKeyMaterialType(), tinkpb.KeyData_SYMMETRIC)
	}
	protoKey := new(aesgcmsivpb.AesGcmSivKey)
	if err := proto.Unmarshal(keyData.GetValue(), protoKey); err != nil {
		return nil, err
	}
	if protoKey.GetVersion() != protoVersion {
		return nil, fmt.Errorf("unsupported version: got %v, want %v", protoKey.GetVersion(), protoVersion)
	}
	variant, err := variantFromProto(keySerialization.OutputPrefixType())
	if err != nil {
		return nil, err
	}
	keySizeInBytes := len(protoKey.GetKeyValue())
	params, err := NewParameters(keySizeInBytes, variant)
	if err != nil {
		return nil, err
	}
	keyMaterial := secretdata.NewBytesFromData(protoKey.GetKeyValue(), insecuresecretdataaccess.Token{})
	// keySerialization.IDRequirement() returns zero if the key doesn't have a
	// key requirement.
	keyID, _ := keySerialization.IDRequirement()
	return NewKey(keyMaterial, keyID, params)
}

type parametersSerializer struct{}

var _ protoserialization.ParametersSerializer = (*parametersSerializer)(nil)

func (s *parametersSerializer) Serialize(parameters key.Parameters) (*tinkpb.KeyTemplate, error) {
	actualParameters, ok := parameters.(*Parameters)
	if !ok {
		return nil, fmt.Errorf("invalid parameters type: got %T, want *aesgcmsiv.Parameters", parameters)
	}
	outputPrefixType, err := protoOutputPrefixTypeFromVariant(actualParameters.Variant())
	if err != nil {
		return nil, err
	}
	format := &aesgcmsivpb.AesGcmSivKeyFormat{
		KeySize: uint32(actualParameters.KeySizeInBytes()),
	}
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          typeURL,
		OutputPrefixType: outputPrefixType,
		Value:            serializedFormat,
	}, nil
}