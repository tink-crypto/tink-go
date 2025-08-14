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

package jwt

import (
	"fmt"

	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtecdsa"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/signature/ecdsa"
)

func ecdsaCurveAndHashFromJWTAlgorithm(algorithm jwtecdsa.Algorithm) (ecdsa.CurveType, ecdsa.HashType, error) {
	switch algorithm {
	case jwtecdsa.ES256:
		return ecdsa.NistP256, ecdsa.SHA256, nil
	case jwtecdsa.ES384:
		return ecdsa.NistP384, ecdsa.SHA384, nil
	case jwtecdsa.ES512:
		return ecdsa.NistP521, ecdsa.SHA512, nil
	default:
		return ecdsa.UnknownCurveType, ecdsa.UnknownHashType, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// Full implementation of the [Signer] interface.
type jwtECDSASigner struct {
	sKID *signerWithKID
	// keyID is set only for TINK keys. Keys with Custom KID or that ignores
	// it are RAW, thus this is nil.
	keyID *string
}

var _ Signer = (*jwtECDSASigner)(nil)

func (s *jwtECDSASigner) SignAndEncode(rawJWT *RawJWT) (string, error) {
	return s.sKID.SignAndEncodeWithKID(rawJWT, s.keyID)
}

func createJWTECDSASigner(key key.Key) (any, error) {
	privateKey, ok := key.(*jwtecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected %T, got %T", (*jwtecdsa.PrivateKey)(nil), key)
	}
	publicKey, err := privateKey.PublicKey()
	if err != nil {
		return nil, err
	}
	jwtPublicKey := publicKey.(*jwtecdsa.PublicKey)
	jwtParams := privateKey.Parameters().(*jwtecdsa.Parameters)
	curveType, hashType, err := ecdsaCurveAndHashFromJWTAlgorithm(jwtParams.Algorithm())
	if err != nil {
		return nil, err
	}
	ecdsaParams, err := ecdsa.NewParameters(curveType, hashType, ecdsa.IEEEP1363, ecdsa.VariantNoPrefix)
	if err != nil {
		return nil, err
	}
	ecdsaPrivateKey, err := ecdsa.NewPrivateKey(privateKey.PrivateKeyValue(), 0, ecdsaParams)
	if err != nil {
		return nil, err
	}
	ecdsaSigner, err := ecdsa.NewSigner(ecdsaPrivateKey, internalapi.Token{})
	if err != nil {
		return nil, err
	}

	kid, _ := jwtPublicKey.KID()
	var sKID *signerWithKID
	if jwtParams.KIDStrategy() == jwtecdsa.CustomKID {
		// In this case we do have a KID, but it is custom, so we pass it to
		// newSignerWithKID, and set a nil kid.
		sKID, err = newSignerWithKID(ecdsaSigner, jwtParams.Algorithm().String(), &kid)
	} else {
		// No custom KID, the key is either TINK or RAW.
		sKID, err = newSignerWithKID(ecdsaSigner, jwtParams.Algorithm().String(), nil)
	}
	if err != nil {
		return nil, err
	}

	if jwtParams.KIDStrategy() == jwtecdsa.Base64EncodedKeyIDAsKID {
		// TINK.
		return &jwtECDSASigner{
			sKID:  sKID,
			keyID: &kid,
		}, nil
	}
	// RAW.
	return &jwtECDSASigner{
		sKID:  sKID,
		keyID: nil,
	}, nil
}
