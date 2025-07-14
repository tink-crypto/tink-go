// Copyright 2022 Google LLC
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

	pb "github.com/tink-crypto/tink-go/v2/proto/hpke_go_proto"
)

// newPrimitivesFromProto constructs new KEM, KDF, AEADs from HpkeParams.
func newPrimitivesFromProto(params *pb.HpkeParams) (kem, kdf, aead, error) {
	kemID, err := kemIDFromProto(params.GetKem())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("kemIDFromProto(%d): %v", params.GetKem(), err)
	}
	kem, err := newKEM(kemID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("newKEM(%d): %v", kemID, err)
	}

	kdfID, err := kdfIDFromProto(params.GetKdf())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("kdfIDFromProto(%d): %v", params.GetKdf(), err)
	}
	kdf, err := newKDF(kdfID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("newKDF(%d): %v", kdfID, err)
	}

	aeadID, err := aeadIDFromProto(params.GetAead())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("aeadIDFromProto(%d): %v", params.GetAead(), err)
	}
	aead, err := newAEAD(aeadID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("newAEAD(%d): %v", aeadID, err)
	}

	return kem, kdf, aead, nil
}

// newKEM constructs a HPKE KEM using kemID, which are specified at
// https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.
func newKEM(kemID KEMID) (kem, error) {
	switch kemID {
	case P256HKDFSHA256:
		return newNISTCurvesKEM(P256HKDFSHA256)
	case P384HKDFSHA384:
		return newNISTCurvesKEM(P384HKDFSHA384)
	case P521HKDFSHA512:
		return newNISTCurvesKEM(P521HKDFSHA512)
	case X25519HKDFSHA256:
		return newX25519KEM(SHA256)
	default:
		return nil, fmt.Errorf("KEM ID %d is not supported", kemID)
	}
}

// kemIDFromProto returns the KEM ID from the HpkeKem enum value. KEM IDs are
// specified at
// https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.
func kemIDFromProto(enum pb.HpkeKem) (KEMID, error) {
	switch enum {
	case pb.HpkeKem_DHKEM_P256_HKDF_SHA256:
		return P256HKDFSHA256, nil
	case pb.HpkeKem_DHKEM_P384_HKDF_SHA384:
		return P384HKDFSHA384, nil
	case pb.HpkeKem_DHKEM_P521_HKDF_SHA512:
		return P521HKDFSHA512, nil
	case pb.HpkeKem_DHKEM_X25519_HKDF_SHA256:
		return X25519HKDFSHA256, nil
	default:
		return 0, fmt.Errorf("HpkeKem enum value %d is not supported", enum)
	}
}

// newKDF constructs a HPKE KDF using kdfID, which are specified at
// https://www.rfc-editor.org/rfc/rfc9180.html#section-7.2.
func newKDF(kdfID KDFID) (kdf, error) {
	switch kdfID {
	case HKDFSHA256:
		return newHKDFKDF(SHA256)
	case HKDFSHA384:
		return newHKDFKDF(SHA384)
	case HKDFSHA512:
		return newHKDFKDF(SHA512)
	default:
		return nil, fmt.Errorf("KDF ID %d is not supported", kdfID)
	}
}

// kdfIDFromProto returns the KDF ID from the HpkeKdf enum value. KDF IDs are
// specified at
// https://www.rfc-editor.org/rfc/rfc9180.html#section-7.2.
func kdfIDFromProto(enum pb.HpkeKdf) (KDFID, error) {
	if enum == pb.HpkeKdf_HKDF_SHA256 {
		return HKDFSHA256, nil
	}
	if enum == pb.HpkeKdf_HKDF_SHA384 {
		return HKDFSHA384, nil
	}
	if enum == pb.HpkeKdf_HKDF_SHA512 {
		return HKDFSHA512, nil
	}
	return 0, fmt.Errorf("HpkeKdf enum value %d is not supported", enum)
}

// newAEAD constructs a HPKE AEAD using aeadID, which are specified at
// https://www.rfc-editor.org/rfc/rfc9180.html#section-7.3.
func newAEAD(aeadID AEADID) (aead, error) {
	switch aeadID {
	case AES128GCM:
		return newAESGCMAEAD(16)
	case AES256GCM:
		return newAESGCMAEAD(32)
	case ChaCha20Poly1305:
		return &chaCha20Poly1305AEAD{}, nil
	default:
		return nil, fmt.Errorf("AEAD ID %d is not supported", aeadID)
	}
}

// aeadIDFromProto returns the AEAD ID from the HpkeAead enum value. AEAD IDs
// are specified at
// https://www.rfc-editor.org/rfc/rfc9180.html#section-7.3.
func aeadIDFromProto(enum pb.HpkeAead) (AEADID, error) {
	switch enum {
	case pb.HpkeAead_AES_128_GCM:
		return AES128GCM, nil
	case pb.HpkeAead_AES_256_GCM:
		return AES256GCM, nil
	case pb.HpkeAead_CHACHA20_POLY1305:
		return ChaCha20Poly1305, nil
	default:
		return 0, fmt.Errorf("HpkeAead enum value %d is not supported", enum)
	}
}
