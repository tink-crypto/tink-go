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
	"slices"

	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/key"
	signaturesubtle "github.com/tink-crypto/tink-go/v2/signature/subtle"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// verifier implements the [tink.Verifier] interface for ECDSA (RFC6979).
//
// It accepts signature in both ASN.1 and IEEE_P1363 encoding.
type verifier struct {
	impl    *signaturesubtle.ECDSAVerifier
	prefix  []byte
	variant Variant
}

var _ tink.Verifier = (*verifier)(nil)

// NewVerifier creates a new ECDSA Verifier.
//
// This is an internal API.
func NewVerifier(publicKey *PublicKey, _ internalapi.Token) (tink.Verifier, error) {
	hashType := publicKey.parameters.HashType().String()
	encoding := publicKey.parameters.SignatureEncoding().String()
	curve := publicKey.parameters.CurveType().String()
	x, y, err := validateEncodingAndGetCoordinates(publicKey.publicPoint, publicKey.parameters.CurveType())
	if err != nil {
		return nil, err
	}
	rawPrimitive, err := signaturesubtle.NewECDSAVerifier(hashType, curve, encoding, x, y)
	if err != nil {
		return nil, err
	}
	return &verifier{
		impl:    rawPrimitive,
		prefix:  publicKey.OutputPrefix(),
		variant: publicKey.parameters.Variant(),
	}, nil
}

// Verify verifies whether the given signature is valid for the given data.
//
// The signature is expected to be of the form: prefix || signature, where
// prefix is the key's output prefix and can be empty, and signature is the
// signature in the encoding specified by the key's parameters.
func (e *verifier) Verify(signatureBytes, data []byte) error {
	if !bytes.HasPrefix(signatureBytes, e.prefix) {
		return fmt.Errorf("ecdsa_verifier: invalid signature prefix")
	}
	toSign := data
	if e.variant == VariantLegacy {
		toSign = slices.Concat(data, []byte{0})
	}
	return e.impl.Verify(signatureBytes[len(e.prefix):], toSign)
}

func verifierConstructor(key key.Key) (any, error) {
	that, ok := key.(*PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not a *ecdsa.PublicKey")
	}
	return NewVerifier(that, internalapi.Token{})
}
