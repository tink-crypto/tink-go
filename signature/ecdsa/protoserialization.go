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

package ecdsa

import (
	"bytes"
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	ecdsapb "github.com/tink-crypto/tink-go/v2/proto/ecdsa_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

type publicKeySerializer struct{}

func protoOutputPrefixTypeFromVariant(variant Variant) (tinkpb.OutputPrefixType, error) {
	switch variant {
	case VariantTink:
		return tinkpb.OutputPrefixType_TINK, nil
	case VariantLegacy:
		return tinkpb.OutputPrefixType_LEGACY, nil
	case VariantCrunchy:
		return tinkpb.OutputPrefixType_CRUNCHY, nil
	case VariantNoPrefix:
		return tinkpb.OutputPrefixType_RAW, nil
	default:
		return tinkpb.OutputPrefixType_UNKNOWN_PREFIX, fmt.Errorf("unknown output prefix variant: %v", variant)
	}
}

func protoCurveFromCurveType(curveType CurveType) (commonpb.EllipticCurveType, error) {
	switch curveType {
	case NistP256:
		return commonpb.EllipticCurveType_NIST_P256, nil
	case NistP384:
		return commonpb.EllipticCurveType_NIST_P384, nil
	case NistP521:
		return commonpb.EllipticCurveType_NIST_P521, nil
	default:
		return commonpb.EllipticCurveType_UNKNOWN_CURVE, fmt.Errorf("unknown curve type: %v", curveType)
	}
}

func protoHashTypeFromHashType(hashType HashType) (commonpb.HashType, error) {
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

func protoEcdsaSignatureEncodingFromSignatureEncoding(encoding SignatureEncoding) (ecdsapb.EcdsaSignatureEncoding, error) {
	switch encoding {
	case DER:
		return ecdsapb.EcdsaSignatureEncoding_DER, nil
	case IEEEP1363:
		return ecdsapb.EcdsaSignatureEncoding_IEEE_P1363, nil
	default:
		return ecdsapb.EcdsaSignatureEncoding_UNKNOWN_ENCODING, fmt.Errorf("unknown hash type: %v", encoding)
	}
}

func createProtoECDSAParams(p *Parameters) (*ecdsapb.EcdsaParams, error) {
	curve, err := protoCurveFromCurveType(p.CurveType())
	if err != nil {
		return nil, err
	}
	hash, err := protoHashTypeFromHashType(p.HashType())
	if err != nil {
		return nil, err
	}
	encoding, err := protoEcdsaSignatureEncodingFromSignatureEncoding(p.SignatureEncoding())
	if err != nil {
		return nil, err
	}
	return &ecdsapb.EcdsaParams{
		Curve:    curve,
		HashType: hash,
		Encoding: encoding,
	}, nil
}

// validateEncodingAndGetCoordinates validates the encoding of a public point
// and returns the x and y coordinates. Encoding must be as per [SEC 1 v2.0,
// Section 2.3.3]. This function adds an extra leading 0x00 byte to the
// coordinates for compatibility with other Tink implementations (see
// b/264525021).
//
// [SEC 1 v2.0, Section 2.3.3]: https://www.secg.org/sec1-v2.pdf#page=17.08
func validateEncodingAndGetCoordinates(publicPoint []byte, curveType CurveType) ([]byte, []byte, error) {
	coordinateSize, err := coordinateSizeForCurve(curveType)
	if err != nil {
		return nil, nil, err
	}

	if len(publicPoint) != 2*coordinateSize+1 {
		return nil, nil, fmt.Errorf("public key point has invalid coordinate size: got %v, want %v", len(publicPoint), 2*coordinateSize+1)
	}

	if publicPoint[0] != 0x04 {
		return nil, nil, fmt.Errorf("public key has invalid 1st byte: got %x, want %x", publicPoint[0], 0x04)
	}
	xy := publicPoint[1:]
	x := make([]byte, 1, coordinateSize+1)
	y := make([]byte, 1, coordinateSize+1)
	x = append(x, xy[:coordinateSize]...)
	y = append(y, xy[coordinateSize:]...)
	return x, y, nil
}

func createProtoECDSAPublicKey(k *PublicKey, p *Parameters) (*ecdsapb.EcdsaPublicKey, error) {
	protoECDSAParams, err := createProtoECDSAParams(p)
	if err != nil {
		return nil, err
	}

	x, y, err := validateEncodingAndGetCoordinates(k.PublicPoint(), p.CurveType())
	if err != nil {
		return nil, err
	}

	return &ecdsapb.EcdsaPublicKey{
		Version: verifierKeyVersion,
		Params:  protoECDSAParams,
		X:       x,
		Y:       y,
	}, nil
}

func (s *publicKeySerializer) SerializeKey(key key.Key) (*protoserialization.KeySerialization, error) {
	ecdsaPublicKey, ok := key.(*PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not an ecdsa.PublicKey object")
	}

	ecdsaParameters, ok := ecdsaPublicKey.Parameters().(*Parameters)
	if !ok {
		return nil, fmt.Errorf("ecdsaPublicKey.Parameters() is not *ecdsa.Parameters")
	}

	// This is nil if PublicKey was created as a struct literal.
	if ecdsaParameters == nil {
		return nil, fmt.Errorf("ecdsaParameters is nil")
	}

	outputPrefixType, err := protoOutputPrefixTypeFromVariant(ecdsaParameters.Variant())
	if err != nil {
		return nil, err
	}

	protoECDSAKey, err := createProtoECDSAPublicKey(ecdsaPublicKey, ecdsaParameters)
	if err != nil {
		return nil, err
	}
	protoECDSAKeyBytes, err := proto.Marshal(protoECDSAKey)
	if err != nil {
		return nil, err
	}

	// idRequirement is zero if the key doesn't have a key requirement.
	idRequirement, _ := ecdsaPublicKey.IDRequirement()
	keyData := &tinkpb.KeyData{
		TypeUrl:         verifierTypeURL,
		Value:           protoECDSAKeyBytes,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}
	return protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
}

type publicKeyParser struct{}

func variantFromProto(outputPrefixType tinkpb.OutputPrefixType) (Variant, error) {
	switch outputPrefixType {
	case tinkpb.OutputPrefixType_TINK:
		return VariantTink, nil
	case tinkpb.OutputPrefixType_LEGACY:
		return VariantLegacy, nil
	case tinkpb.OutputPrefixType_CRUNCHY:
		return VariantCrunchy, nil
	case tinkpb.OutputPrefixType_RAW:
		return VariantNoPrefix, nil
	default:
		return VariantUnknown, fmt.Errorf("unknown output prefix: %v", outputPrefixType)
	}
}

func curveTypeFromProto(curveType commonpb.EllipticCurveType) (CurveType, error) {
	switch curveType {
	case commonpb.EllipticCurveType_NIST_P256:
		return NistP256, nil
	case commonpb.EllipticCurveType_NIST_P384:
		return NistP384, nil
	case commonpb.EllipticCurveType_NIST_P521:
		return NistP521, nil
	default:
		return UnknownCurveType, fmt.Errorf("unknown curve type: %v", curveType)
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
		return UnknownHashType, fmt.Errorf("unknown hash type: %v", hashType)
	}
}

func signatureEncodingFromProto(encoding ecdsapb.EcdsaSignatureEncoding) (SignatureEncoding, error) {
	switch encoding {
	case ecdsapb.EcdsaSignatureEncoding_DER:
		return DER, nil
	case ecdsapb.EcdsaSignatureEncoding_IEEE_P1363:
		return IEEEP1363, nil
	default:
		return UnknownSignatureEncoding, fmt.Errorf("unknown signature encoding: %v", encoding)
	}
}

func coordinateSizeForCurve(curveType CurveType) (int, error) {
	switch curveType {
	case NistP256:
		return 32, nil
	case NistP384:
		return 48, nil
	case NistP521:
		return 66, nil
	default:
		return 0, fmt.Errorf("unsupported curve: %v", curveType)
	}
}

// encodePoint encodes a public point in uncompressed format as per [SEC 1
// v2.0, Section 2.3.3].
//
// The encoding is of the form "0x04 || x || y", where x and y are the byte
// representations of the coordinates of the public point.
// The byte representation of the public point coordinates may be smaller
// than the curve size, in which case we have to pad them with a prefix of
// zeros.
//
// [SEC 1 v2.0, Section 2.3.3]: https://www.secg.org/sec1-v2.pdf#page=17.08
func encodePoint(x, y []byte, coordinateSize int) []byte {
	encodedPoint := make([]byte, 1+2*coordinateSize)

	encodedPoint[0] = 0x04

	xStartPos := 1 + coordinateSize - len(x)
	copy(encodedPoint[xStartPos:], x)

	yStartPos := 1 + coordinateSize + coordinateSize - len(y)
	copy(encodedPoint[yStartPos:], y)

	return encodedPoint
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
	protoECDSAKey := new(ecdsapb.EcdsaPublicKey)
	if err := proto.Unmarshal(keyData.GetValue(), protoECDSAKey); err != nil {
		return nil, err
	}
	if protoECDSAKey.GetVersion() > verifierKeyVersion {
		return nil, fmt.Errorf("public key has unsupported version: %v", protoECDSAKey.GetVersion())
	}
	variant, err := variantFromProto(keySerialization.OutputPrefixType())
	if err != nil {
		return nil, err
	}
	curveType, err := curveTypeFromProto(protoECDSAKey.GetParams().GetCurve())
	if err != nil {
		return nil, err
	}
	hashType, err := hashTypeFromProto(protoECDSAKey.GetParams().GetHashType())
	if err != nil {
		return nil, err
	}
	signatureEncoding, err := signatureEncodingFromProto(protoECDSAKey.GetParams().GetEncoding())
	if err != nil {
		return nil, err
	}
	params, err := NewParameters(curveType, hashType, signatureEncoding, variant)
	if err != nil {
		return nil, err
	}
	coordinateSize, err := coordinateSizeForCurve(curveType)
	if err != nil {
		return nil, err
	}

	// Tolerate arbitrary leading zeros in the coordinates.
	// This is to support the case where the curve size in bytes + 1 is the
	// length of the coordinate. This happens when Tink adds an extra leading
	// 0x00 byte (see b/264525021).
	x := bytes.TrimLeft(protoECDSAKey.GetX(), "\x00")
	y := bytes.TrimLeft(protoECDSAKey.GetY(), "\x00")

	if len(x) > coordinateSize || len(y) > coordinateSize {
		return nil, fmt.Errorf("public key has invalid coordinate size: (%v, %v)", len(x), len(y))
	}

	publicPoint := encodePoint(x, y, coordinateSize)
	// keySerialization.IDRequirement() returns zero if the key doesn't have a key requirement.
	keyID, _ := keySerialization.IDRequirement()
	return NewPublicKey(publicPoint, keyID, params)
}