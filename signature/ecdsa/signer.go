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
	"github.com/tink-crypto/tink-go/v2/tink"
)

// signer is an implementation of the [tink.Signer] interface for ECDSA
// (RFC6979).
type signer struct {
	key        *ecdsa.PrivateKey
	prefix     []byte
	parameters *Parameters
	hashFunc   func() hash.Hash
}

var _ tink.Signer = (*signer)(nil)

// NewSigner creates a new instance of [Signer].
//
// It assumes that the private key k is valid.
//
// This is an internal API.
func NewSigner(k *PrivateKey, _ internalapi.Token) (tink.Signer, error) {
	params := k.publicKey.parameters
	hashFunc, err := hashFunctionFromEnum(params.HashType())
	if err != nil {
		return nil, err
	}
	curve, err := curveFromTinkECDSACurveType(params.CurveType())
	if err != nil {
		return nil, err
	}

	publicPoint := k.publicKey.PublicPoint()
	// The point is guaranteed to be encoded as per SEC 1 v2.0, Section 2.3.3
	// https://www.secg.org/sec1-v2.pdf#page=17.08.
	xy := publicPoint[1:]
	ecdsaPrivateKey := new(ecdsa.PrivateKey)
	ecdsaPrivateKey.PublicKey.Curve = curve
	ecdsaPrivateKey.PublicKey.X = new(big.Int).SetBytes(xy[:len(xy)/2])
	ecdsaPrivateKey.PublicKey.Y = new(big.Int).SetBytes(xy[len(xy)/2:])

	ecdsaPrivateKey.D = new(big.Int).SetBytes(k.PrivateKeyValue().Data(insecuresecretdataaccess.Token{}))

	return &signer{
		key:        ecdsaPrivateKey,
		prefix:     k.OutputPrefix(),
		hashFunc:   hashFunc,
		parameters: params,
	}, nil
}

func signImpl(pk *ecdsa.PrivateKey, hashed []byte, encoding SignatureEncoding) ([]byte, error) {
	switch encoding {
	case IEEEP1363:
		r, s, err := ecdsa.Sign(rand.Reader, pk, hashed)
		if err != nil {
			return nil, err
		}
		sig := internalecdsa.Signature{R: r, S: s}
		return internalecdsa.IEEEP1363Encode(&sig, pk.PublicKey.Curve.Params().Name)
	case DER:
		return ecdsa.SignASN1(rand.Reader, pk, hashed)
	default:
		return nil, fmt.Errorf("unsupported encoding: %s", encoding)
	}
}

// Sign computes a signature for the given data.
//
// The returned signature is of the form: prefix || signature, where prefix is
// the key's output prefix which can be empty, and signature is the signature
// in the encoding specified by the key's parameters.
func (e *signer) Sign(data []byte) ([]byte, error) {
	h := e.hashFunc()
	h.Write(data)
	if e.parameters.Variant() == VariantLegacy {
		h.Write([]byte{0})
	}
	hashed := h.Sum(nil)
	encoding := e.parameters.SignatureEncoding()
	signatureBytes, err := signImpl(e.key, hashed, encoding)
	if err != nil {
		return nil, fmt.Errorf("ecdsa_signer: signing failed: %s", err)
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
