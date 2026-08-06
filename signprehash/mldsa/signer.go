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

package mldsa

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	internalmldsa "github.com/tink-crypto/tink-go/v2/internal/signature/mldsa"
	"github.com/tink-crypto/tink-go/v2/key"
	tinkmldsa "github.com/tink-crypto/tink-go/v2/signature/mldsa"
	"github.com/tink-crypto/tink-go/v2/tink"
)

type prehashSigner struct {
	secretKey *internalmldsa.SecretKey
	keyID     [4]byte
}

var _ tink.PrehashSigner = (*prehashSigner)(nil)

func mldsaSecretKeyFromPrivateKey(privateKey *tinkmldsa.PrivateKey) (*internalmldsa.SecretKey, error) {
	params, ok := privateKey.Parameters().(*tinkmldsa.Parameters)
	if !ok {
		return nil, fmt.Errorf("invalid parameters type: %T", privateKey.Parameters())
	}
	seedBytes := privateKey.PrivateKeyBytes().Data(insecuresecretdataaccess.Token{})
	if len(seedBytes) != internalmldsa.SecretKeySeedSize {
		return nil, fmt.Errorf("invalid seed length: %d", len(seedBytes))
	}
	var seed [internalmldsa.SecretKeySeedSize]byte
	copy(seed[:], seedBytes)

	switch params.Instance() {
	case tinkmldsa.MLDSA44:
		_, sk := internalmldsa.MLDSA44.KeyGenFromSeed(seed)
		return sk, nil
	case tinkmldsa.MLDSA65:
		_, sk := internalmldsa.MLDSA65.KeyGenFromSeed(seed)
		return sk, nil
	case tinkmldsa.MLDSA87:
		_, sk := internalmldsa.MLDSA87.KeyGenFromSeed(seed)
		return sk, nil
	default:
		return nil, fmt.Errorf("invalid instance: %v", params.Instance())
	}
}

// NewPrehashSigner creates a new [tink.PrehashSigner] for ML-DSA External Mu keys.
func NewPrehashSigner(privateKey *tinkmldsa.PrivateKey, _ internalapi.Token) (tink.PrehashSigner, error) {
	params, ok := privateKey.Parameters().(*tinkmldsa.Parameters)
	if !ok {
		return nil, fmt.Errorf("invalid parameters type")
	}
	if params.Variant() == tinkmldsa.VariantNoPrefix {
		return nil, fmt.Errorf("mldsa.NewPrehashSigner: key variant must not be VariantNoPrefix, got %v", params.Variant())
	}
	secretKey, err := mldsaSecretKeyFromPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	keyID, _ := privateKey.IDRequirement()
	s := &prehashSigner{secretKey: secretKey}
	binary.BigEndian.PutUint32(s.keyID[:], keyID)
	return s, nil
}

func (s *prehashSigner) SignPrehash(prehash []byte) ([]byte, error) {
	// prehash ?= 0xFF || keyID(4 bytes) || mu(64 bytes).
	if len(prehash) != 5+64 {
		return nil, fmt.Errorf("mldsa.prehashSigner: prehash must be 64 bytes, got %d", len(prehash))
	}
	if prehash[0] != startByte {
		return nil, fmt.Errorf("mldsa.prehashSigner: prehash must start with 0xff, got %x", prehash[0])
	}
	if !bytes.Equal(s.keyID[:], prehash[1:5]) {
		return nil, fmt.Errorf("mldsa.prehashSigner: key ID mismatch, got %x, want %x", prehash[1:5], s.keyID)
	}
	var mu [64]byte
	copy(mu[:], prehash[5:])
	return s.secretKey.SignWithMu(mu), nil
}

func prehashSignerConstructor(k key.Key) (any, error) {
	privateKey, ok := k.(*tinkmldsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not a %T", (*tinkmldsa.PrivateKey)(nil))
	}
	return NewPrehashSigner(privateKey, internalapi.Token{})
}
