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

// Package xwing implements the X-Wing KEM defined in
// https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-10.html.
package xwing

import (
	"crypto/mlkem"
	"crypto/sha3"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/subtle"
)

const (
	xWingLabel     = `\.//^\`
	secretKeySize  = 32
	publicKeySize  = 1216
	ciphertextSize = 1120
)

// Encapsulate computes a new encapsulated shared secret.
func Encapsulate(publicKey []byte) (sharedSecret, ciphertext []byte, err error) {
	if len(publicKey) != publicKeySize {
		return nil, nil, fmt.Errorf("invalid public key length: %d, want %d", len(publicKey), publicKeySize)
	}

	pkM := publicKey[:mlkem.EncapsulationKeySize768]
	pkX := publicKey[mlkem.EncapsulationKeySize768:]

	// Compute X25519 shared secret.
	ekX, err := subtle.GeneratePrivateKeyX25519()
	if err != nil {
		return nil, nil, err
	}
	ctX, err := subtle.PublicFromPrivateX25519(ekX)
	if err != nil {
		return nil, nil, err
	}
	ssX, err := subtle.ComputeSharedSecretX25519(ekX, pkX)
	if err != nil {
		return nil, nil, err
	}

	// ML-KEM-768 encapsulation.
	ekM, err := mlkem.NewEncapsulationKey768(pkM)
	if err != nil {
		return nil, nil, err
	}
	ssM, ctM := ekM.Encapsulate()

	// Combine secrets.
	ss := combiner(ssM, ssX, ctX, pkX)

	// encapsulatedKey = ctM || ctX.
	ct := make([]byte, 0, ciphertextSize)
	ct = append(ct, ctM...)
	ct = append(ct, ctX...)

	return ss, ct, nil
}

// Decapsulate computes the shared secret from the encapsulated key.
func Decapsulate(ciphertext, recipientPrivKey []byte) ([]byte, error) {
	if len(ciphertext) != ciphertextSize {
		return nil, fmt.Errorf("invalid ciphertext length: %d, want %d", len(ciphertext), ciphertextSize)
	}

	seedM, skX, err := expandDecapsulationKey(recipientPrivKey)
	if err != nil {
		return nil, err
	}

	ctM := ciphertext[:mlkem.CiphertextSize768]
	ctX := ciphertext[mlkem.CiphertextSize768:]

	// ML-KEM-768 decapsulation.
	dkM, err := mlkem.NewDecapsulationKey768(seedM)
	if err != nil {
		return nil, err
	}
	ssM, err := dkM.Decapsulate(ctM)
	if err != nil {
		return nil, err
	}

	// Compute X25519 shared secret.
	ssX, err := subtle.ComputeSharedSecretX25519(skX, ctX)
	if err != nil {
		return nil, err
	}
	pkX, err := subtle.PublicFromPrivateX25519(skX)
	if err != nil {
		return nil, err
	}

	// Combine secrets.
	ss := combiner(ssM, ssX, ctX, pkX)

	return ss, nil
}

// PublicFromSecret computes the X-Wing public key from the X-Wing secret key.
func PublicFromSecret(secretKey []byte) ([]byte, error) {
	if len(secretKey) != secretKeySize {
		return nil, fmt.Errorf("invalid secret key length: %d, want %d", len(secretKey), secretKeySize)
	}

	seedM, skX, err := expandDecapsulationKey(secretKey)
	if err != nil {
		return nil, err
	}

	// Compute ML-KEM-768 public key.
	skM, err := mlkem.NewDecapsulationKey768(seedM)
	if err != nil {
		return nil, err
	}
	pkM := skM.EncapsulationKey().Bytes()

	// Compute X25519 public key.
	pkX, err := subtle.PublicFromPrivateX25519(skX)
	if err != nil {
		return nil, err
	}

	publicKey := make([]byte, 0, publicKeySize)
	publicKey = append(publicKey, pkM...)
	publicKey = append(publicKey, pkX...)

	return publicKey, nil
}

func expandDecapsulationKey(secretKey []byte) (seedM []byte, skX []byte, err error) {
	if len(secretKey) != secretKeySize {
		return nil, nil, fmt.Errorf("invalid secret key length: %d, want %d", len(secretKey), secretKeySize)
	}

	// Expand the 32-byte secret key using SHAKE-256.
	s := sha3.NewSHAKE256()
	s.Write(secretKey)
	seedM = make([]byte, 64)
	s.Read(seedM)
	skX = make([]byte, 32)
	s.Read(skX)

	return seedM, skX, nil
}

func combiner(ssM, ssX, ctX, pkX []byte) []byte {
	// Combine secrets using SHA3-256.
	h := sha3.New256()
	h.Write(ssM)
	h.Write(ssX)
	h.Write(ctX)
	h.Write(pkX)
	h.Write([]byte(xWingLabel))
	return h.Sum(nil)
}
