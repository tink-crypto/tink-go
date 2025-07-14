// Copyright 2021 Google LLC
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

package hpke

import (
	"fmt"

	"github.com/tink-crypto/tink-go/v2/subtle"
)

var (
	x25519KEMGeneratePrivateKey = subtle.GeneratePrivateKeyX25519
	x25519KEMPublicFromPrivate  = subtle.PublicFromPrivateX25519
)

// x25519KEM is a Diffie-Hellman-based X25519 HPKE KEM variant that implements
// interface kem.
type x25519KEM struct {
	// HPKE KEM algorithm identifier.
	kemID   KEMID
	hashAlg HashType
}

var _ kem = (*x25519KEM)(nil)

// newX25519KEM constructs a X25519 HPKE KEM using hashAlg.
func newX25519KEM(hashAlg HashType) (*x25519KEM, error) {
	if hashAlg == SHA256 {
		return &x25519KEM{kemID: X25519HKDFSHA256, hashAlg: SHA256}, nil
	}
	return nil, fmt.Errorf("HASH algorithm %s is not supported", hashAlg)
}

func (x *x25519KEM) encapsulate(recipientPubKey []byte) (sharedSecret, senderPubKey []byte, err error) {
	senderPrivKey, err := x25519KEMGeneratePrivateKey()
	if err != nil {
		return nil, nil, err
	}
	dh, err := subtle.ComputeSharedSecretX25519(senderPrivKey, recipientPubKey)
	if err != nil {
		return nil, nil, err
	}
	senderPubKey, err = x25519KEMPublicFromPrivate(senderPrivKey)
	if err != nil {
		return nil, nil, err
	}
	sharedSecret, err = x.deriveKEMSharedSecret(dh, senderPubKey, recipientPubKey)
	if err != nil {
		return nil, nil, err
	}
	return sharedSecret, senderPubKey, nil
}

func (x *x25519KEM) decapsulate(encapsulatedKey, recipientPrivKey []byte) ([]byte, error) {
	dh, err := subtle.ComputeSharedSecretX25519(recipientPrivKey, encapsulatedKey)
	if err != nil {
		return nil, err
	}
	recipientPubKey, err := x25519KEMPublicFromPrivate(recipientPrivKey)
	if err != nil {
		return nil, err
	}
	return x.deriveKEMSharedSecret(dh, encapsulatedKey, recipientPubKey)
}

func (x *x25519KEM) id() KEMID { return x.kemID }

func (x *x25519KEM) encapsulatedKeyLength() int { return kemLengths[x.kemID].nEnc }

// deriveKEMSharedSecret returns a pseudorandom key obtained via HKDF SHA256.
func (x *x25519KEM) deriveKEMSharedSecret(dh, senderPubKey, recipientPubKey []byte) ([]byte, error) {
	ctx := make([]byte, 0, len(senderPubKey)+len(recipientPubKey))
	ctx = append(ctx, senderPubKey...)
	ctx = append(ctx, recipientPubKey...)

	suiteID := kemSuiteID(X25519HKDFSHA256)
	macLength, err := subtle.GetHashDigestSize(x.hashAlg.String())
	if err != nil {
		return nil, err
	}
	hkdfKDF, err := newHKDFKDF(x.hashAlg)
	if err != nil {
		return nil, err
	}
	return hkdfKDF.extractAndExpand(
		nil, /*=salt*/
		dh,
		"eae_prk",
		ctx,
		"shared_secret",
		suiteID,
		int(macLength))
}
