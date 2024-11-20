// Copyright 2020 Google LLC
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

package subtle

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"hash"
	"math/big"

	internalecdsa "github.com/tink-crypto/tink-go/v2/internal/signature/ecdsa"
	"github.com/tink-crypto/tink-go/v2/subtle"
)

// ECDSAVerifier is an implementation of Verifier for ECDSA.
// At the moment, the implementation only accepts signatures with strict DER encoding.
type ECDSAVerifier struct {
	publicKey *ecdsa.PublicKey
	hashFunc  func() hash.Hash
	encoding  string
}

// NewECDSAVerifier creates a new instance of ECDSAVerifier.
func NewECDSAVerifier(hashAlg string, curve string, encoding string, x []byte, y []byte) (*ECDSAVerifier, error) {
	publicKey := &ecdsa.PublicKey{
		Curve: subtle.GetCurve(curve),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
	return NewECDSAVerifierFromPublicKey(hashAlg, encoding, publicKey)
}

// NewECDSAVerifierFromPublicKey creates a new instance of ECDSAVerifier.
func NewECDSAVerifierFromPublicKey(hashAlg string, encoding string, publicKey *ecdsa.PublicKey) (*ECDSAVerifier, error) {
	if publicKey.Curve == nil {
		return nil, errors.New("ecdsa_verifier: invalid curve")
	}
	if !publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		return nil, fmt.Errorf("ecdsa_verifier: invalid public key")
	}
	curve := subtle.ConvertCurveName(publicKey.Curve.Params().Name)
	if err := ValidateECDSAParams(hashAlg, curve, encoding); err != nil {
		return nil, fmt.Errorf("ecdsa_verifier: %s", err)
	}
	hashFunc := subtle.GetHashFunc(hashAlg)
	return &ECDSAVerifier{
		publicKey: publicKey,
		hashFunc:  hashFunc,
		encoding:  encoding,
	}, nil
}

// Verify verifies whether the given signature is valid for the given data.
// It returns an error if the signature is not valid; nil otherwise.
func (e *ECDSAVerifier) Verify(signatureBytes, data []byte) error {
	hashed, err := subtle.ComputeHash(e.hashFunc, data)
	if err != nil {
		return err
	}
	var asn1Signature []byte
	switch e.encoding {
	case "DER":
		asn1Signature = signatureBytes
	case "IEEE_P1363":
		decodedSig, err := internalecdsa.IEEEP1363Decode(signatureBytes)
		if err != nil {
			return err
		}
		asn1Signature, err = internalecdsa.ASN1Encode(decodedSig)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("ecdsa: unsupported encoding: %s", e.encoding)
	}
	if ok := ecdsa.VerifyASN1(e.publicKey, hashed, asn1Signature); !ok {
		return fmt.Errorf("ecdsa_verifier: invalid signature")
	}
	return nil
}
