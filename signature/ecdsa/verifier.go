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
	"crypto/ecdsa"
	"fmt"
	"hash"
	"slices"

	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	internalecdsa "github.com/tink-crypto/tink-go/v2/internal/signature/ecdsa"
	"github.com/tink-crypto/tink-go/v2/subtle"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// verifier implements the [tink.Verifier] interface for ECDSA (RFC6979).
//
// It accepts signature in both ASN.1 and IEEE_P1363 encoding.
type verifier struct {
	publicKey *ecdsa.PublicKey
	hashFunc  func() hash.Hash
	encoding  SignatureEncoding
	prefix    []byte
	variant   Variant
}

var _ tink.Verifier = (*verifier)(nil)

// NewVerifier creates a new ECDSA Verifier.
//
// This is an internal API.
func NewVerifier(publicKey *PublicKey, _ internalapi.Token) (tink.Verifier, error) {
	pk, err := ecdsaPublicKey(publicKey.parameters, publicKey.publicPoint)
	if err != nil {
		return nil, err
	}
	return &verifier{
		publicKey: pk,
		hashFunc:  subtle.GetHashFunc(publicKey.parameters.HashType().String()),
		encoding:  publicKey.parameters.SignatureEncoding(),
		prefix:    publicKey.OutputPrefix(),
		variant:   publicKey.parameters.Variant(),
	}, nil
}

// Verify verifies whether the given signature is valid for the given data.
//
// The signature is expected to be of the form:
//
//	<prefix> || signature
//
// where prefix is the key's output prefix and can be empty, and signature is
// the signature in the encoding specified by the key's parameters.
func (e *verifier) Verify(signatureBytes, data []byte) error {
	if !bytes.HasPrefix(signatureBytes, e.prefix) {
		return fmt.Errorf("ecdsa_verifier: invalid signature prefix")
	}
	toSign := data
	if e.variant == VariantLegacy {
		toSign = slices.Concat(data, []byte{0})
	}
	hashed, err := subtle.ComputeHash(e.hashFunc, toSign)
	if err != nil {
		return err
	}

	rawSignature := signatureBytes[len(e.prefix):]
	var asn1Signature []byte
	switch e.encoding {
	case DER:
		asn1Signature = rawSignature
	case IEEEP1363:
		decodedSig, err := internalecdsa.IEEEP1363Decode(rawSignature)
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
