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

package ecies

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	eciespb "github.com/tink-crypto/tink-go/v2/proto/ecies_aead_hkdf_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const publicKeyTypeURL = "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey"

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

func protoCurveFromCurveType(curveType CurveType) (commonpb.EllipticCurveType, error) {
	switch curveType {
	case NISTP256:
		return commonpb.EllipticCurveType_NIST_P256, nil
	case NISTP384:
		return commonpb.EllipticCurveType_NIST_P384, nil
	case NISTP521:
		return commonpb.EllipticCurveType_NIST_P521, nil
	case X25519:
		return commonpb.EllipticCurveType_CURVE25519, nil
	default:
		return commonpb.EllipticCurveType_UNKNOWN_CURVE, fmt.Errorf("unknown curve type: %v", curveType)
	}
}

func protoHashTypeFromHashType(hashType HashType) (commonpb.HashType, error) {
	switch hashType {
	case SHA1:
		return commonpb.HashType_SHA1, nil
	case SHA224:
		return commonpb.HashType_SHA224, nil
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

func protoEcPointFormatFromPointFormat(pointFormat PointFormat) (commonpb.EcPointFormat, error) {
	switch pointFormat {
	case CompressedPointFormat:
		return commonpb.EcPointFormat_COMPRESSED, nil
	case UncompressedPointFormat:
		return commonpb.EcPointFormat_UNCOMPRESSED, nil
	case UnspecifiedPointFormat:
		// This is unspecified only for X25519, so we set it to COMPRESSED.
		return commonpb.EcPointFormat_COMPRESSED, nil
	default:
		return commonpb.EcPointFormat_UNKNOWN_FORMAT, fmt.Errorf("unknown point format: %v ", pointFormat)
	}
}

func createProtoECIESParams(p *Parameters) (*eciespb.EciesAeadHkdfParams, error) {
	curveType, err := protoCurveFromCurveType(p.CurveType())
	if err != nil {
		return nil, err
	}

	protoHashType, err := protoHashTypeFromHashType(p.HashType())
	if err != nil {
		return nil, err
	}

	protoDEMParams, err := protoserialization.SerializeParameters(p.DEMParameters())
	if err != nil {
		return nil, err
	}

	pointFormat, err := protoEcPointFormatFromPointFormat(p.NISTCurvePointFormat())
	if err != nil {
		return nil, err
	}

	return &eciespb.EciesAeadHkdfParams{
		KemParams: &eciespb.EciesHkdfKemParams{
			CurveType:    curveType,
			HkdfHashType: protoHashType,
			HkdfSalt:     p.Salt(),
		},
		DemParams: &eciespb.EciesAeadDemParams{
			AeadDem: protoDEMParams,
		},
		EcPointFormat: pointFormat,
	}, nil
}

func coordinateSizeForCurve(curveType CurveType) (int, error) {
	switch curveType {
	case NISTP256:
		return 32, nil
	case NISTP384:
		return 48, nil
	case NISTP521:
		return 66, nil
	default:
		return 0, fmt.Errorf("unsupported curve: %v", curveType)
	}
}

// padBigIntBytesToFixedSizeBuffer pads the given big integer bytes to the given size.
func padBigIntBytesToFixedSizeBuffer(bigIntBytes []byte, size int) ([]byte, error) {
	if len(bigIntBytes) > size {
		return nil, fmt.Errorf("big int has invalid size: %d, want at most %d", len(bigIntBytes), size)
	}
	if len(bigIntBytes) == size {
		return bigIntBytes, nil
	}
	buf := make([]byte, size-len(bigIntBytes), size)
	return append(buf, bigIntBytes...), nil
}

func (s *publicKeySerializer) SerializeKey(key key.Key) (*protoserialization.KeySerialization, error) {
	eciesPublicKey, ok := key.(*PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is of type %T, want %T", key, (*PublicKey)(nil))
	}
	eciesParams := eciesPublicKey.Parameters().(*Parameters)
	// This is nil if PublicKey was created as a struct literal.
	if eciesParams == nil {
		return nil, fmt.Errorf("key has nil parameters")
	}

	protoECIESParams, err := createProtoECIESParams(eciesParams)
	if err != nil {
		return nil, err
	}

	protoPublicKey := &eciespb.EciesAeadHkdfPublicKey{
		Version: 0,
		Params:  protoECIESParams,
	}

	switch eciesParams.CurveType() {
	case NISTP256, NISTP384, NISTP521:
		// Encoding must be as per [SEC 1 v2.0, Section 2.3.3]. This function adds
		// an extra leading 0x00 byte to the coordinates for compatibility with
		// other Tink implementations (see b/264525021).
		coordinateSize, err := coordinateSizeForCurve(eciesParams.CurveType())
		if err != nil {
			return nil, err
		}
		if len(eciesPublicKey.PublicKeyBytes()) != 2*coordinateSize+1 {
			return nil, fmt.Errorf("public key point has invalid coordinate size: got %v, want %v", len(eciesPublicKey.PublicKeyBytes()), 2*coordinateSize+1)
		}
		if eciesPublicKey.PublicKeyBytes()[0] != 0x04 {
			return nil, fmt.Errorf("public key has invalid 1st byte: got %x, want %x", eciesPublicKey.PublicKeyBytes()[0], 0x04)
		}
		xy := eciesPublicKey.PublicKeyBytes()[1:]
		protoPublicKey.X, err = padBigIntBytesToFixedSizeBuffer(xy[:coordinateSize], coordinateSize+1)
		if err != nil {
			return nil, err
		}
		protoPublicKey.Y, err = padBigIntBytesToFixedSizeBuffer(xy[coordinateSize:], coordinateSize+1)
		if err != nil {
			return nil, err
		}
	case X25519:
		protoPublicKey.X = eciesPublicKey.PublicKeyBytes()
	default:
		return nil, fmt.Errorf("unsupported curve type: %v", eciesParams.CurveType())
	}

	serializedECIESPubKey, err := proto.Marshal(protoPublicKey)
	if err != nil {
		return nil, err
	}

	outputPrefixType, err := protoOutputPrefixTypeFromVariant(eciesParams.Variant())
	if err != nil {
		return nil, err
	}

	// idRequirement is zero if the key doesn't have a key requirement.
	idRequirement, _ := eciesPublicKey.IDRequirement()
	keyData := &tinkpb.KeyData{
		TypeUrl:         publicKeyTypeURL,
		Value:           serializedECIESPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}
	return protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
}
