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

package rsassapkcs1

import (
	"fmt"
	"math/big"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	rsassapkcs1pb "github.com/tink-crypto/tink-go/v2/proto/rsa_ssa_pkcs1_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	// publicKeyProtoVersion is the accepted [rsassapkcs1pb.RsaSsaPkcs1PublicKey] proto
	// version.
	//
	// Currently, only version 0 is supported; other versions are rejected.
	publicKeyProtoVersion = 0
	// privateKeyProtoVersion is the accepted [rsassapkcs1pb.RsaSsaPkcs1PrivateKey] proto
	// version.
	//
	// Currently, only version 0 is supported; other versions are rejected.
	privateKeyProtoVersion = 0
)

type publicKeySerializer struct{}

var _ protoserialization.KeySerializer = (*publicKeySerializer)(nil)

func protoOutputPrefixTypeFromVariant(variant Variant) (tinkpb.OutputPrefixType, error) {
	switch variant {
	case VariantTink:
		return tinkpb.OutputPrefixType_TINK, nil
	case VariantCrunchy:
		return tinkpb.OutputPrefixType_CRUNCHY, nil
	case VariantLegacy:
		return tinkpb.OutputPrefixType_LEGACY, nil
	case VariantNoPrefix:
		return tinkpb.OutputPrefixType_RAW, nil
	default:
		return tinkpb.OutputPrefixType_UNKNOWN_PREFIX, fmt.Errorf("unknown output prefix variant: %v", variant)
	}
}

func protoHashValueFromHashType(hashType HashType) (commonpb.HashType, error) {
	switch hashType {
	case SHA256:
		return commonpb.HashType_SHA256, nil
	case SHA384:
		return commonpb.HashType_SHA384, nil
	case SHA512:
		return commonpb.HashType_SHA512, nil
	default:
		return commonpb.HashType_UNKNOWN_HASH, fmt.Errorf("unknown hash type: %v", hashType)
	}
}

func (s *publicKeySerializer) SerializeKey(key key.Key) (*protoserialization.KeySerialization, error) {
	rsaPublicKey, ok := key.(*PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid key type: %T, want *rsassapkcs1.PublicKey", key)
	}
	if rsaPublicKey.parameters == nil {
		return nil, fmt.Errorf("invalid key")
	}
	outputPrefixType, err := protoOutputPrefixTypeFromVariant(rsaPublicKey.parameters.Variant())
	if err != nil {
		return nil, err
	}
	hashType, err := protoHashValueFromHashType(rsaPublicKey.parameters.HashType())
	if err != nil {
		return nil, err
	}
	protoKey := &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
		Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
			HashType: hashType,
		},
		N:       rsaPublicKey.Modulus(),
		E:       new(big.Int).SetUint64(uint64(rsaPublicKey.parameters.PublicExponent())).Bytes(),
		Version: publicKeyProtoVersion,
	}
	serializedKey, err := proto.Marshal(protoKey)
	if err != nil {
		return nil, err
	}
	// idRequirement is zero if the key doesn't have a key requirement.
	idRequirement, _ := rsaPublicKey.IDRequirement()
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
	case tinkpb.OutputPrefixType_CRUNCHY:
		return VariantCrunchy, nil
	case tinkpb.OutputPrefixType_LEGACY:
		return VariantLegacy, nil
	case tinkpb.OutputPrefixType_RAW:
		return VariantNoPrefix, nil
	default:
		return VariantUnknown, fmt.Errorf("unsupported output prefix type: %v", prefixType)
	}
}

func hashTypeFromProto(hashType commonpb.HashType) (HashType, error) {
	switch hashType {
	case commonpb.HashType_SHA256:
		return SHA256, nil
	case commonpb.HashType_SHA384:
		return SHA384, nil
	case commonpb.HashType_SHA512:
		return SHA512, nil
	default:
		return UnknownHashType, fmt.Errorf("unsupported hash type: %v", hashType)
	}
}

func (s *publicKeyParser) ParseKey(keySerialization *protoserialization.KeySerialization) (key.Key, error) {
	keyData := keySerialization.KeyData()
	if keyData.GetTypeUrl() != verifierTypeURL {
		return nil, fmt.Errorf("invalid key type URL: %v", keyData.GetTypeUrl())
	}
	if keyData.GetKeyMaterialType() != tinkpb.KeyData_ASYMMETRIC_PUBLIC {
		return nil, fmt.Errorf("invalid key material type: %v", keyData.GetKeyMaterialType())
	}
	protoKey := new(rsassapkcs1pb.RsaSsaPkcs1PublicKey)
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
	hashType, err := hashTypeFromProto(protoKey.GetParams().GetHashType())
	if err != nil {
		return nil, err
	}
	modulus := protoKey.GetN()
	exponent := new(big.Int).SetBytes(protoKey.GetE())
	params, err := NewParameters(new(big.Int).SetBytes(modulus).BitLen(), hashType, int(exponent.Int64()), variant)
	if err != nil {
		return nil, err
	}
	// keySerialization.IDRequirement() returns zero if the key doesn't have a key requirement.
	keyID, _ := keySerialization.IDRequirement()
	return NewPublicKey(modulus, keyID, params)
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
	protoPrivateKey := new(rsassapkcs1pb.RsaSsaPkcs1PrivateKey)
	if err := proto.Unmarshal(keyData.GetValue(), protoPrivateKey); err != nil {
		return nil, err
	}
	if protoPrivateKey.GetVersion() != privateKeyProtoVersion {
		return nil, fmt.Errorf("private key has unsupported version: %v", protoPrivateKey.GetVersion())
	}
	variant, err := variantFromProto(keySerialization.OutputPrefixType())
	if err != nil {
		return nil, err
	}
	protoPublicKey := protoPrivateKey.GetPublicKey()
	hashType, err := hashTypeFromProto(protoPublicKey.GetParams().GetHashType())
	if err != nil {
		return nil, err
	}
	modulus := protoPublicKey.GetN()
	exponent := new(big.Int).SetBytes(protoPublicKey.GetE())
	params, err := NewParameters(new(big.Int).SetBytes(modulus).BitLen(), hashType, int(exponent.Int64()), variant)
	if err != nil {
		return nil, err
	}
	if protoPublicKey.GetVersion() != publicKeyProtoVersion {
		return nil, fmt.Errorf("public key has unsupported version: %v", protoPublicKey.GetVersion())
	}
	// keySerialization.IDRequirement() returns zero if the key doesn't have a key requirement.
	keyID, _ := keySerialization.IDRequirement()
	publicKey, err := NewPublicKey(modulus, keyID, params)
	if err != nil {
		return nil, err
	}
	token := insecuresecretdataaccess.Token{}
	return NewPrivateKey(publicKey, PrivateKeyValues{
		P: secretdata.NewBytesFromData(protoPrivateKey.GetP(), token),
		Q: secretdata.NewBytesFromData(protoPrivateKey.GetQ(), token),
		D: secretdata.NewBytesFromData(protoPrivateKey.GetD(), token),
	})
}

type privateKeySerializer struct{}

var _ protoserialization.KeySerializer = (*privateKeySerializer)(nil)

func (s *privateKeySerializer) SerializeKey(key key.Key) (*protoserialization.KeySerialization, error) {
	rsaSsaPrivKey, ok := key.(*PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid key type: %T, want *rsassapkcs1.PrivateKey", key)
	}
	if rsaSsaPrivKey.publicKey == nil {
		return nil, fmt.Errorf("invalid key: public key is nil")
	}
	params := rsaSsaPrivKey.publicKey.parameters
	outputPrefixType, err := protoOutputPrefixTypeFromVariant(params.Variant())
	if err != nil {
		return nil, err
	}
	hashType, err := protoHashValueFromHashType(params.HashType())
	if err != nil {
		return nil, err
	}

	token := insecuresecretdataaccess.Token{}
	protoKey := &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
		P:   rsaSsaPrivKey.P().Data(token),
		Q:   rsaSsaPrivKey.Q().Data(token),
		D:   rsaSsaPrivKey.D().Data(token),
		Dp:  rsaSsaPrivKey.DP().Data(token),
		Dq:  rsaSsaPrivKey.DQ().Data(token),
		Crt: rsaSsaPrivKey.QInv().Data(token),
		PublicKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
			Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
				HashType: hashType,
			},
			N:       rsaSsaPrivKey.publicKey.Modulus(),
			E:       new(big.Int).SetUint64(uint64(rsaSsaPrivKey.publicKey.parameters.PublicExponent())).Bytes(),
			Version: publicKeyProtoVersion,
		},
		Version: privateKeyProtoVersion,
	}
	serializedKey, err := proto.Marshal(protoKey)
	if err != nil {
		return nil, err
	}
	// idRequirement is zero if the key doesn't have a key requirement.
	idRequirement, _ := rsaSsaPrivKey.IDRequirement()
	keyData := &tinkpb.KeyData{
		TypeUrl:         signerTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}
	return protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
}