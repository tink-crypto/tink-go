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
	"crypto/rand"
	"errors"
	"fmt"
	"hash"
	"math/big"

	"github.com/tink-crypto/tink-go/v2/subtle"
)

// ECDSASigner is an implementation of Signer for ECDSA.
// At the moment, the implementation only accepts DER encoding.
type ECDSASigner struct {
	privateKey *ecdsa.PrivateKey
	hashFunc   func() hash.Hash
	encoding   string
}

// NewECDSASigner creates a new instance of ECDSASigner.
func NewECDSASigner(hashAlg, curve, encoding string, keyValue []byte) (*ECDSASigner, error) {
	privKey := new(ecdsa.PrivateKey)
	c := subtle.GetCurve(curve)
	if c == nil {
		return nil, errors.New("ecdsa_signer: invalid curve")
	}
	privKey.PublicKey.Curve = c
	privKey.D = new(big.Int).SetBytes(keyValue)
	privKey.PublicKey.X, privKey.PublicKey.Y = c.ScalarBaseMult(keyValue)
	return NewECDSASignerFromPrivateKey(hashAlg, encoding, privKey)
}

// NewECDSASignerFromPrivateKey creates a new instance of ECDSASigner
func NewECDSASignerFromPrivateKey(hashAlg, encoding string, privateKey *ecdsa.PrivateKey) (*ECDSASigner, error) {
	if privateKey.Curve == nil {
		return nil, errors.New("ecdsa_signer: privateKey.Curve can't be nil")
	}
	curve := subtle.ConvertCurveName(privateKey.Curve.Params().Name)
	if err := ValidateECDSAParams(hashAlg, curve, encoding); err != nil {
		return nil, fmt.Errorf("ecdsa_signer: %s", err)
	}
	hashFunc := subtle.GetHashFunc(hashAlg)
	return &ECDSASigner{
		privateKey: privateKey,
		hashFunc:   hashFunc,
		encoding:   encoding,
	}, nil
}

// Sign computes a signature for the given data.
func (e *ECDSASigner) Sign(data []byte) ([]byte, error) {
	hashed, err := subtle.ComputeHash(e.hashFunc, data)
	if err != nil {
		return nil, err
	}
	var signatureBytes []byte
	switch e.encoding {
	case "IEEE_P1363":
		r, s, err := ecdsa.Sign(rand.Reader, e.privateKey, hashed)
		if err != nil {
			return nil, err
		}
		sig := NewECDSASignature(r, s)
		signatureBytes, err = sig.EncodeECDSASignature(e.encoding, e.privateKey.PublicKey.Curve.Params().Name)
		if err != nil {
			return nil, fmt.Errorf("ecdsa_signer: signing failed: %s", err)
		}
	case "DER":
		signatureBytes, err = ecdsa.SignASN1(rand.Reader, e.privateKey, hashed)
		if err != nil {
			return nil, fmt.Errorf("ecdsa_signer: signing failed: %s", err)
		}
	default:
		return nil, fmt.Errorf("ecdsa_signer: unsupported encoding: %s", e.encoding)
	}
	return signatureBytes, nil
}
