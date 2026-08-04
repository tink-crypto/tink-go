// Copyright 2026 Google LLC
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

// Package mldsa implements the ML-DSA prehash primitive.
package mldsa

import (
	"encoding/binary"
	"fmt"
	"slices"

	"golang.org/x/crypto/sha3"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	internalmldsa "github.com/tink-crypto/tink-go/v2/internal/signature/mldsa"
	"github.com/tink-crypto/tink-go/v2/key"

	tinkmldsa "github.com/tink-crypto/tink-go/v2/signature/mldsa"
	"github.com/tink-crypto/tink-go/v2/tink"
)

const (
	startByte = 0xff
)

type prehash struct {
	tr    [64]byte
	keyID uint32
}

var _ tink.Prehash = (*prehash)(nil)

func mldsaPublicKeyFromPublicKey(publicKey *tinkmldsa.PublicKey) (*internalmldsa.PublicKey, error) {
	params, ok := publicKey.Parameters().(*tinkmldsa.Parameters)
	if !ok {
		return nil, fmt.Errorf("invalid parameters type: %T", publicKey.Parameters())
	}
	rawPubKeyBytes := publicKey.KeyBytes()

	switch params.Instance() {
	case tinkmldsa.MLDSA44:
		return internalmldsa.MLDSA44.DecodePublicKey(rawPubKeyBytes)
	case tinkmldsa.MLDSA65:
		return internalmldsa.MLDSA65.DecodePublicKey(rawPubKeyBytes)
	case tinkmldsa.MLDSA87:
		return internalmldsa.MLDSA87.DecodePublicKey(rawPubKeyBytes)
	default:
		return nil, fmt.Errorf("invalid instance: %v", params.Instance())
	}
}

// NewPrehash creates a new [tink.Prehash] primitive for ML-DSA External Mu public keys.
func NewPrehash(publicKey *tinkmldsa.PublicKey, _ internalapi.Token) (tink.Prehash, error) {
	params, ok := publicKey.Parameters().(*tinkmldsa.Parameters)
	if !ok {
		return nil, fmt.Errorf("invalid parameters type")
	}
	// Cannot create prehash for VariantNoPrefix keys because Tink always adds a key-specific
	// prefix to the prehash value.
	if params.Variant() == tinkmldsa.VariantNoPrefix {
		return nil, fmt.Errorf("mldsa.NewPrehash: key variant must not be VariantNoPrefix, got %v", params.Variant())
	}
	keyID, hasID := publicKey.IDRequirement()
	if !hasID {
		return nil, fmt.Errorf("mldsa.NewPrehash: key must have ID requirement")
	}
	internalPubKey, err := mldsaPublicKeyFromPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return &prehash{
		tr:    internalPubKey.TR(),
		keyID: keyID,
	}, nil
}

func (c *prehash) ComputePrehash(data []byte) ([]byte, error) {
	// payload = 0xFF || keyID(4) || mu(64).
	payload := make([]byte, 5+64)
	payload[0] = startByte
	binary.BigEndian.PutUint32(payload[1:5], c.keyID)
	sha3.ShakeSum256(payload[5:], slices.Concat(c.tr[:], []byte{0, 0}, data))
	return payload, nil
}

func prehashConstructor(k key.Key) (any, error) {
	publicKey, ok := k.(*tinkmldsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not a %T", (*tinkmldsa.PublicKey)(nil))
	}
	return NewPrehash(publicKey, internalapi.Token{})
}
