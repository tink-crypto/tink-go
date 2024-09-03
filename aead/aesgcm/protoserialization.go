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

package aesgcm

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	gcmpb "github.com/tink-crypto/tink-go/v2/proto/aes_gcm_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	// protoVersion is the accepted [gcmpb.AesGcmKey] proto version.
	//
	// Currently, only version 0 is supported; other versions are rejected.
	protoVersion = 0
)

type serializer struct{}

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

func (s *serializer) SerializeKey(key key.Key) (*tinkpb.Keyset_Key, error) {
	actualKey, ok := key.(*Key)
	if !ok {
		return nil, fmt.Errorf("key is not a Key")
	}
	actualParameters, ok := actualKey.Parameters().(*Parameters)
	if !ok {
		return nil, fmt.Errorf("key parameters is not a Parameters")
	}
	outputPrefixType, err := protoOutputPrefixTypeFromVariant(actualParameters.Variant())
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
	protoKeysetKey := &tinkpb.Keyset_Key{
		KeyData: &tinkpb.KeyData{
			TypeUrl:         typeURL,
			Value:           serializedKey,
			KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
		},
		OutputPrefixType: outputPrefixType,
		// NOTE: Status is expected to be set by the keyset.
	}
	// Set the key ID only if we have an ID requirement.
	keyID, isRequired := actualKey.IDRequirement()
	if isRequired {
		protoKeysetKey.KeyId = keyID
	}
	return protoKeysetKey, nil
}

type parser struct{}

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

func (s *parser) ParseKey(keysetKey *tinkpb.Keyset_Key) (key.Key, error) {
	if keysetKey == nil {
		return nil, fmt.Errorf("keyset key is nil")
	}
	keyData := keysetKey.GetKeyData()
	if keyData.GetTypeUrl() != typeURL {
		return nil, fmt.Errorf("key is not an AES GCM key")
	}
	if keyData.GetKeyMaterialType() != tinkpb.KeyData_SYMMETRIC {
		return nil, fmt.Errorf("key is not a SYMMETRIC key")
	}
	protoKey := new(gcmpb.AesGcmKey)
	if err := proto.Unmarshal(keyData.GetValue(), protoKey); err != nil {
		return nil, err
	}
	if protoKey.GetVersion() != protoVersion {
		return nil, fmt.Errorf("key has unsupported version: %v", protoKey.GetVersion())
	}
	variant, err := variantFromProto(keysetKey.GetOutputPrefixType())
	if err != nil {
		return nil, err
	}
	keySizeInBytes := len(protoKey.GetKeyValue())
	params, err := NewParameters(ParametersOpts{
		KeySizeInBytes: keySizeInBytes,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        variant,
	})
	if err != nil {
		return nil, err
	}
	keyMaterial := secretdata.NewBytesFromData(protoKey.GetKeyValue(), insecuresecretdataaccess.Token{})
	keyID := keysetKey.GetKeyId()
	if variant == VariantNoPrefix {
		keyID = 0
	}
	return NewKey(*keyMaterial, keyID, params)
}
