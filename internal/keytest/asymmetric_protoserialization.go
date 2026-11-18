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

package keytest

import (
	"bytes"
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	testonlypb "github.com/tink-crypto/tink-go/v2/proto/test_only_key_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	// publicKeyProtoVersion is the accepted [testonlypb.TestOnlyPublicKey] proto
	// version.
	//
	// Currently, only version 0 is supported; other versions are rejected.
	publicKeyProtoVersion = 0
	// privateKeyProtoVersion is the accepted [testonlypb.TestOnlyPrivateKey]
	// proto version.
	//
	// Currently, only version 0 is supported; other versions are rejected.
	privateKeyProtoVersion = 0

	publicKeyTypeURL  = "type.googleapis.com/google.crypto.tink.TestOnlyPublicKey"
	privateKeyTypeURL = "type.googleapis.com/google.crypto.tink.TestOnlyPrivateKey"
)

type publicKeySerializer struct{}

var _ protoserialization.KeySerializer = (*publicKeySerializer)(nil)

func (s *publicKeySerializer) SerializeKey(key key.Key) (*protoserialization.KeySerialization, error) {
	publicKey, ok := key.(*PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid key type: got %T, want *keytest.PublicKey", key)
	}
	// This fails if publicKey was not created with NewPublicKey.
	outputPrefixType, err := protoOutputPrefixTypeFromVariant(publicKey.parameters.Variant())
	if err != nil {
		return nil, err
	}
	protoKey := &testonlypb.TestOnlyPublicKey{
		Version:  publicKeyProtoVersion,
		KeyValue: publicKey.KeyBytes(),
	}
	serializedKey, err := proto.Marshal(protoKey)
	if err != nil {
		return nil, err
	}
	// idRequirement is zero if the key doesn't have an ID requirement.
	idRequirement, _ := publicKey.IDRequirement()
	keyData := &tinkpb.KeyData{
		TypeUrl:         publicKeyTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}
	return protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
}

type privateKeySerializer struct{}

var _ protoserialization.KeySerializer = (*privateKeySerializer)(nil)

func (s *privateKeySerializer) SerializeKey(key key.Key) (*protoserialization.KeySerialization, error) {
	privateKey, ok := key.(*PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid key type: got %T, want *keytest.PrivateKey", key)
	}
	if privateKey.publicKey == nil {
		return nil, fmt.Errorf("invalid key: public key is nil")
	}
	outputPrefixType, err := protoOutputPrefixTypeFromVariant(privateKey.publicKey.parameters.Variant())
	if err != nil {
		return nil, err
	}
	protoKey := &testonlypb.TestOnlyPrivateKey{
		Version: privateKeyProtoVersion,
		PublicKey: &testonlypb.TestOnlyPublicKey{
			Version:  publicKeyProtoVersion,
			KeyValue: privateKey.publicKey.KeyBytes(),
		},
		KeyValue: privateKey.PrivateKeyBytes().Data(insecuresecretdataaccess.Token{}),
	}
	serializedKey, err := proto.Marshal(protoKey)
	if err != nil {
		return nil, err
	}
	// idRequirement is zero if the key doesn't have an ID requirement.
	idRequirement, _ := privateKey.IDRequirement()
	keyData := &tinkpb.KeyData{
		TypeUrl:         privateKeyTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}
	return protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
}

type publicKeyParser struct{}

var _ protoserialization.KeyParser = (*publicKeyParser)(nil)

func (s *publicKeyParser) ParseKey(keySerialization *protoserialization.KeySerialization) (key.Key, error) {
	if keySerialization == nil {
		return nil, fmt.Errorf("key serialization is nil")
	}
	keyData := keySerialization.KeyData()
	if keyData.GetTypeUrl() != publicKeyTypeURL {
		return nil, fmt.Errorf("invalid type URL: got %q, want %q", keyData.GetTypeUrl(), publicKeyTypeURL)
	}
	if keyData.GetKeyMaterialType() != tinkpb.KeyData_ASYMMETRIC_PUBLIC {
		return nil, fmt.Errorf("invalid key material type: got %v, want %v", keyData.GetKeyMaterialType(), tinkpb.KeyData_ASYMMETRIC_PUBLIC)
	}
	protoKey := new(testonlypb.TestOnlyPublicKey)
	if err := proto.Unmarshal(keyData.GetValue(), protoKey); err != nil {
		return nil, err
	}
	if protoKey.GetVersion() != publicKeyProtoVersion {
		return nil, fmt.Errorf("unsupported public key version: got %d, want %d", protoKey.GetVersion(), publicKeyProtoVersion)
	}
	variant, err := variantFromProto(keySerialization.OutputPrefixType())
	if err != nil {
		return nil, err
	}
	params, err := NewAsymmetricParameters(variant)
	if err != nil {
		return nil, err
	}
	// keySerialization.IDRequirement() returns zero if the key doesn't have an
	// ID requirement.
	keyID, _ := keySerialization.IDRequirement()
	return NewPublicKey(protoKey.GetKeyValue(), keyID, params)
}

type privateKeyParser struct{}

var _ protoserialization.KeyParser = (*privateKeyParser)(nil)

func (s *privateKeyParser) ParseKey(keySerialization *protoserialization.KeySerialization) (key.Key, error) {
	if keySerialization == nil {
		return nil, fmt.Errorf("key serialization is nil")
	}
	keyData := keySerialization.KeyData()
	if keyData.GetTypeUrl() != privateKeyTypeURL {
		return nil, fmt.Errorf("invalid type URL: got %q, want %q", keyData.GetTypeUrl(), privateKeyTypeURL)
	}
	if keyData.GetKeyMaterialType() != tinkpb.KeyData_ASYMMETRIC_PRIVATE {
		return nil, fmt.Errorf("invalid key material type: got %v, want %v", keyData.GetKeyMaterialType(), tinkpb.KeyData_ASYMMETRIC_PRIVATE)
	}
	protoKey := new(testonlypb.TestOnlyPrivateKey)
	if err := proto.Unmarshal(keyData.GetValue(), protoKey); err != nil {
		return nil, err
	}
	if protoKey.GetVersion() != privateKeyProtoVersion {
		return nil, fmt.Errorf("unsupported private key version: got %d, want %d", protoKey.GetVersion(), privateKeyProtoVersion)
	}
	if protoKey.GetPublicKey() == nil {
		return nil, fmt.Errorf("invalid private key: public key is not set")
	}
	if protoKey.GetPublicKey().GetVersion() != publicKeyProtoVersion {
		return nil, fmt.Errorf("unsupported public key version: got %d, want %d", protoKey.GetPublicKey().GetVersion(), publicKeyProtoVersion)
	}
	variant, err := variantFromProto(keySerialization.OutputPrefixType())
	if err != nil {
		return nil, err
	}
	params, err := NewAsymmetricParameters(variant)
	if err != nil {
		return nil, err
	}
	privateKeyBytes := secretdata.NewBytesFromData(protoKey.GetKeyValue(), insecuresecretdataaccess.Token{})
	// keySerialization.IDRequirement() returns zero if the key doesn't have an
	// ID requirement.
	keyID, _ := keySerialization.IDRequirement()
	privateKey, err := NewPrivateKey(privateKeyBytes, keyID, params)
	if err != nil {
		return nil, err
	}
	// Make sure the serialized public key is the one of the private key, that
	// is, the private key bytes in reverse order.
	if !bytes.Equal(protoKey.GetPublicKey().GetKeyValue(), privateKey.publicKey.keyBytes) {
		return nil, fmt.Errorf("invalid private key: public key does not match private key")
	}
	return privateKey, nil
}

type asymmetricParametersSerializer struct{}

var _ protoserialization.ParametersSerializer = (*asymmetricParametersSerializer)(nil)

func (s *asymmetricParametersSerializer) Serialize(parameters key.Parameters) (*tinkpb.KeyTemplate, error) {
	actualParameters, ok := parameters.(*AsymmetricParameters)
	if !ok {
		return nil, fmt.Errorf("invalid parameters type: got %T, want *keytest.AsymmetricParameters", parameters)
	}
	outputPrefixType, err := protoOutputPrefixTypeFromVariant(actualParameters.Variant())
	if err != nil {
		return nil, err
	}
	format := &testonlypb.TestOnlyKeyFormat{
		KeySize: keySizeInBytes,
	}
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          privateKeyTypeURL,
		OutputPrefixType: outputPrefixType,
		Value:            serializedFormat,
	}, nil
}

type asymmetricParametersParser struct{}

var _ protoserialization.ParametersParser = (*asymmetricParametersParser)(nil)

func (s *asymmetricParametersParser) Parse(keyTemplate *tinkpb.KeyTemplate) (key.Parameters, error) {
	if keyTemplate.GetTypeUrl() != privateKeyTypeURL {
		return nil, fmt.Errorf("invalid type URL: got %q, want %q", keyTemplate.GetTypeUrl(), privateKeyTypeURL)
	}
	format := new(testonlypb.TestOnlyKeyFormat)
	if err := proto.Unmarshal(keyTemplate.GetValue(), format); err != nil {
		return nil, err
	}
	if format.GetKeySize() != keySizeInBytes {
		return nil, fmt.Errorf("unsupported key size: got %d, want %d", format.GetKeySize(), keySizeInBytes)
	}
	variant, err := variantFromProto(keyTemplate.GetOutputPrefixType())
	if err != nil {
		return nil, err
	}
	return NewAsymmetricParameters(variant)
}
