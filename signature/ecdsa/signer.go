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
	"fmt"
	"slices"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/signature/subtle"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// signer is an implementation of the [tink.Signer] interface for ECDSA
// (RFC6979).
type signer struct {
	impl    *subtle.ECDSASigner
	prefix  []byte
	variant Variant
}

var _ tink.Signer = (*signer)(nil)

// NewSigner creates a new instance of [Signer].
//
// This is an internal API.
func NewSigner(k *PrivateKey, _ internalapi.Token) (tink.Signer, error) {
	params := k.publicKey.parameters
	hasType := params.HashType().String()
	encoding := params.SignatureEncoding().String()
	curve := params.CurveType().String()
	rawPrimitive, err := subtle.NewECDSASigner(hasType, curve, encoding, k.PrivateKeyValue().Data(insecuresecretdataaccess.Token{}))
	if err != nil {
		return nil, err
	}
	return &signer{
		impl:    rawPrimitive,
		prefix:  k.OutputPrefix(),
		variant: params.Variant(),
	}, nil
}

// Sign computes a signature for the given data.
//
// The returned signature is of the form: prefix || signature, where prefix is
// the key's output prefix which can be empty, and signature is the signature
// in the encoding specified by the key's parameters.
func (e *signer) Sign(data []byte) ([]byte, error) {
	var toSign = data
	if e.variant == VariantLegacy {
		toSign = slices.Concat(data, []byte{0})
	}
	rawSignature, err := e.impl.Sign(toSign)
	if err != nil {
		return nil, err
	}
	return slices.Concat(e.prefix, rawSignature), nil
}

func signerConstructor(key key.Key) (any, error) {
	that, ok := key.(*PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not a *ecdsa.PrivateKey")
	}
	return NewSigner(that, internalapi.Token{})
}
