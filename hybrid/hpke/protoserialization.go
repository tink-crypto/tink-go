// Copyright 2025 Google LLC
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

package hpke

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	hpkepb "github.com/tink-crypto/tink-go/v2/proto/hpke_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func serializeKEMID(kemID KEMID) (hpkepb.HpkeKem, error) {
	switch kemID {
	case DHKEM_X25519_HKDF_SHA256:
		return hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256, nil
	case DHKEM_P256_HKDF_SHA256:
		return hpkepb.HpkeKem_DHKEM_P256_HKDF_SHA256, nil
	case DHKEM_P384_HKDF_SHA384:
		return hpkepb.HpkeKem_DHKEM_P384_HKDF_SHA384, nil
	case DHKEM_P521_HKDF_SHA512:
		return hpkepb.HpkeKem_DHKEM_P521_HKDF_SHA512, nil
	default:
		return hpkepb.HpkeKem_KEM_UNKNOWN, fmt.Errorf("invalid KEMID: %v", kemID)
	}
}

func serializeAEADID(aeadID AEADID) (hpkepb.HpkeAead, error) {
	switch aeadID {
	case AES128GCM:
		return hpkepb.HpkeAead_AES_128_GCM, nil
	case AES256GCM:
		return hpkepb.HpkeAead_AES_256_GCM, nil
	case ChaCha20Poly1305:
		return hpkepb.HpkeAead_CHACHA20_POLY1305, nil
	default:
		return hpkepb.HpkeAead_AEAD_UNKNOWN, fmt.Errorf("invalid AEADID: %v", aeadID)
	}
}

func serializedKDFID(kdfID KDFID) (hpkepb.HpkeKdf, error) {
	switch kdfID {
	case HKDFSHA256:
		return hpkepb.HpkeKdf_HKDF_SHA256, nil
	case HKDFSHA384:
		return hpkepb.HpkeKdf_HKDF_SHA384, nil
	case HKDFSHA512:
		return hpkepb.HpkeKdf_HKDF_SHA512, nil
	default:
		return hpkepb.HpkeKdf_KDF_UNKNOWN, fmt.Errorf("invalid KDFID: %v", kdfID)
	}
}

func parametersToProto(p *Parameters) (*hpkepb.HpkeParams, error) {
	if p == nil {
		return nil, fmt.Errorf("parameters are nil")
	}
	kemID, err := serializeKEMID(p.KEMID())
	if err != nil {
		return nil, err
	}
	aeadID, err := serializeAEADID(p.AEADID())
	if err != nil {
		return nil, err
	}
	kdfID, err := serializedKDFID(p.KDFID())
	if err != nil {
		return nil, err
	}
	return &hpkepb.HpkeParams{
		Kem:  kemID,
		Kdf:  kdfID,
		Aead: aeadID,
	}, nil
}

func publicKeyToProto(publicKey *PublicKey) (*hpkepb.HpkePublicKey, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("public key is nil")
	}
	protoParameters, err := parametersToProto(publicKey.Parameters().(*Parameters))
	if err != nil {
		return nil, err
	}
	protoPublicKey := &hpkepb.HpkePublicKey{
		Version:   0,
		Params:    protoParameters,
		PublicKey: publicKey.PublicKeyBytes(),
	}
	return protoPublicKey, nil
}

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

type publicKeySerializer struct{}

var _ protoserialization.KeySerializer = (*publicKeySerializer)(nil)

func (s *publicKeySerializer) SerializeKey(key key.Key) (*protoserialization.KeySerialization, error) {
	hpkePublicKey, ok := key.(*PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is of type %T, want %T", key, (*PublicKey)(nil))
	}
	protoPublicKey, err := publicKeyToProto(hpkePublicKey)
	if err != nil {
		return nil, err
	}
	serializedProtoPublicKey, err := proto.Marshal(protoPublicKey)
	if err != nil {
		return nil, err
	}
	keyData := &tinkpb.KeyData{
		TypeUrl:         publicKeyTypeURL,
		Value:           serializedProtoPublicKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}
	outputPrefixType, err := protoOutputPrefixTypeFromVariant(hpkePublicKey.Parameters().(*Parameters).Variant())
	if err != nil {
		return nil, err
	}
	// idRequirement is zero if the key doesn't have a key requirement.
	idRequirement, _ := hpkePublicKey.IDRequirement()
	return protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
}

func parseKEMID(protoKEMID hpkepb.HpkeKem) (KEMID, error) {
	switch protoKEMID {
	case hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256:
		return DHKEM_X25519_HKDF_SHA256, nil
	case hpkepb.HpkeKem_DHKEM_P256_HKDF_SHA256:
		return DHKEM_P256_HKDF_SHA256, nil
	case hpkepb.HpkeKem_DHKEM_P384_HKDF_SHA384:
		return DHKEM_P384_HKDF_SHA384, nil
	case hpkepb.HpkeKem_DHKEM_P521_HKDF_SHA512:
		return DHKEM_P521_HKDF_SHA512, nil
	default:
		return KEMID(0), fmt.Errorf("invalid KEMID: %v", protoKEMID)
	}
}

func parseAEADID(protoAEADID hpkepb.HpkeAead) (AEADID, error) {
	switch protoAEADID {
	case hpkepb.HpkeAead_AES_128_GCM:
		return AES128GCM, nil
	case hpkepb.HpkeAead_AES_256_GCM:
		return AES256GCM, nil
	case hpkepb.HpkeAead_CHACHA20_POLY1305:
		return ChaCha20Poly1305, nil
	default:
		return AEADID(0), fmt.Errorf("invalid AEADID: %v", protoAEADID)
	}
}

func parseKDFID(protoKDFID hpkepb.HpkeKdf) (KDFID, error) {
	switch protoKDFID {
	case hpkepb.HpkeKdf_HKDF_SHA256:
		return HKDFSHA256, nil
	case hpkepb.HpkeKdf_HKDF_SHA384:
		return HKDFSHA384, nil
	case hpkepb.HpkeKdf_HKDF_SHA512:
		return HKDFSHA512, nil
	default:
		return KDFID(0), fmt.Errorf("invalid KDFID: %v", protoKDFID)
	}
}

func protoOutputPrefixTypeToVariant(outputPrefixType tinkpb.OutputPrefixType) (Variant, error) {
	switch outputPrefixType {
	case tinkpb.OutputPrefixType_TINK:
		return VariantTink, nil
	case tinkpb.OutputPrefixType_CRUNCHY:
		return VariantCrunchy, nil
	case tinkpb.OutputPrefixType_RAW:
		return VariantNoPrefix, nil
	default:
		return Variant(0), fmt.Errorf("invalid output prefix type: %v", outputPrefixType)
	}
}

func parsePublicKey(protoPublicKey *hpkepb.HpkePublicKey, outputPrefixType tinkpb.OutputPrefixType, keyID uint32) (key.Key, error) {
	if protoPublicKey.GetVersion() != 0 {
		return nil, fmt.Errorf("invalid key version: %v, want 0", protoPublicKey.GetVersion())
	}
	protoParameters := protoPublicKey.GetParams()
	kemID, err := parseKEMID(protoParameters.GetKem())
	if err != nil {
		return nil, err
	}
	aeadID, err := parseAEADID(protoParameters.GetAead())
	if err != nil {
		return nil, err
	}
	kdfID, err := parseKDFID(protoParameters.GetKdf())
	if err != nil {
		return nil, err
	}
	variant, err := protoOutputPrefixTypeToVariant(outputPrefixType)
	if err != nil {
		return nil, err
	}
	params, err := NewParameters(ParametersOpts{
		KEMID:   kemID,
		AEADID:  aeadID,
		KDFID:   kdfID,
		Variant: variant,
	})
	if err != nil {
		return nil, err
	}
	return NewPublicKey(protoPublicKey.GetPublicKey(), keyID, params)
}

type publicKeyParser struct{}

var _ protoserialization.KeyParser = (*publicKeyParser)(nil)

func (s *publicKeyParser) ParseKey(keySerialization *protoserialization.KeySerialization) (key.Key, error) {
	if keySerialization == nil {
		return nil, fmt.Errorf("key serialization is nil")
	}
	if keySerialization.KeyData() == nil {
		return nil, fmt.Errorf("key data is nil")
	}
	if got, want := keySerialization.KeyData().GetKeyMaterialType(), tinkpb.KeyData_ASYMMETRIC_PUBLIC; got != want {
		return nil, fmt.Errorf("key material type is %v, want %v", got, want)
	}
	protoPublicKey := &hpkepb.HpkePublicKey{}
	if err := proto.Unmarshal(keySerialization.KeyData().GetValue(), protoPublicKey); err != nil {
		return nil, err
	}
	if protoPublicKey.GetVersion() != 0 {
		return nil, fmt.Errorf("invalid key version: %v, want 0", protoPublicKey.GetVersion())
	}
	// keySerialization.IDRequirement() returns zero if the key doesn't have a key requirement.
	keyID, _ := keySerialization.IDRequirement()
	return parsePublicKey(protoPublicKey, keySerialization.OutputPrefixType(), keyID)
}
