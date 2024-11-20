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
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"hash"
	"math/big"
	"slices"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	internalecdsa "github.com/tink-crypto/tink-go/v2/internal/signature/ecdsa"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/subtle"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// signer is an implementation of the [tink.Signer] interface for ECDSA
// (RFC6979).
type signer struct {
	hashFunc   func() hash.Hash
	encoding   SignatureEncoding
	privateKey *ecdsa.PrivateKey
	prefix     []byte
	variant    Variant
}

var _ tink.Signer = (*signer)(nil)

func ecdsaPublicKey(params *Parameters, publicPoint []byte) (*ecdsa.PublicKey, error) {
	x, y, err := validateEncodingAndGetCoordinates(publicPoint, params.CurveType())
	if err != nil {
		return nil, err
	}
	curve := subtle.GetCurve(params.CurveType().String())
	if curve == nil {
		return nil, fmt.Errorf("ecdsa: invalid curve: %s", params.CurveType())
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}, nil
}

// NewSigner creates a new instance of [Signer].
//
// This is an internal API.
func NewSigner(k *PrivateKey, _ internalapi.Token) (tink.Signer, error) {
	params := k.publicKey.parameters
	publicKey, err := ecdsaPublicKey(params, k.publicKey.publicPoint)
	if err != nil {
		return nil, err
	}
	privKey := &ecdsa.PrivateKey{
		PublicKey: *publicKey,
		D:         new(big.Int).SetBytes(k.PrivateKeyValue().Data(insecuresecretdataaccess.Token{})),
	}
	return &signer{
		hashFunc:   subtle.GetHashFunc(params.HashType().String()),
		encoding:   params.SignatureEncoding(),
		privateKey: privKey,
		prefix:     k.OutputPrefix(),
		variant:    params.Variant(),
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
	digest, err := subtle.ComputeHash(e.hashFunc, toSign)
	if err != nil {
		return nil, err
	}
	var signatureBytes []byte
	switch e.encoding {
	case DER:
		var err error
		signatureBytes, err = ecdsa.SignASN1(rand.Reader, e.privateKey, digest)
		if err != nil {
			return nil, err
		}
	case IEEEP1363:
		r, s, err := ecdsa.Sign(rand.Reader, e.privateKey, digest)
		if err != nil {
			return nil, err
		}
		sig := internalecdsa.Signature{R: r, S: s}
		signatureBytes, err = internalecdsa.IEEEP1363Encode(&sig, e.privateKey.PublicKey.Curve.Params().Name)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("ecdsa: unsupported encoding: %s", e.encoding)
	}
	return slices.Concat(e.prefix, signatureBytes), nil
}

func signerConstructor(key key.Key) (any, error) {
	that, ok := key.(*PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not a *ecdsa.PrivateKey")
	}
	return NewSigner(that, internalapi.Token{})
}
