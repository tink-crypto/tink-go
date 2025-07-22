// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/Lycense-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

package jwtecdsa

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/key"
)

// PublicKey represents a public key for JWT ECDSA signing.
type PublicKey struct {
	parameters    *Parameters
	publicPoint   []byte
	idRequirement uint32
	kid           string
	hasKID        bool
}

var _ key.Key = (*PublicKey)(nil)

// ecdhCurveFromAlgorithm returns the corresponding ecdh.Curve value from ct.
func ecdhCurveFromAlgorithm(ct Algorithm) (ecdh.Curve, error) {
	switch ct {
	case ES256:
		return ecdh.P256(), nil
	case ES384:
		return ecdh.P384(), nil
	case ES512:
		return ecdh.P521(), nil
	default:
		return nil, fmt.Errorf("invalid curve type: %v", ct)
	}
}

func computeKID(customKID string, hasCustomKID bool, idRequirement uint32, parameters *Parameters) (string, bool, error) {
	if !hasCustomKID && len(customKID) != 0 {
		return "", false, fmt.Errorf("hasCustomKID is false but customKID is not empty")
	}
	switch parameters.KIDStrategy() {
	case Base64EncodedKeyIDAsKID:
		if hasCustomKID {
			return "", false, fmt.Errorf("custom KID is not supported for KID strategy: %v", parameters.KIDStrategy())
		}
		// Serialize the ID requirement.
		idRequirementBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(idRequirementBytes, idRequirement)
		return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(idRequirementBytes), true, nil
	case IgnoredKID:
		if hasCustomKID {
			return "", false, fmt.Errorf("custom KID is not supported for KID strategy: %v", parameters.KIDStrategy())
		}
		return "", false, nil
	case CustomKID:
		if !hasCustomKID {
			return "", false, fmt.Errorf("custom KID is required for KID strategy: %v", parameters.KIDStrategy())
		}
		return customKID, hasCustomKID, nil
	default:
		return "", false, fmt.Errorf("invalid KID strategy: %v", parameters.KIDStrategy())
	}
}

// PublicKeyOpts are [PublicKey] options.
type PublicKeyOpts struct {
	PublicPoint   []byte
	IDRequirement uint32
	CustomKID     string
	HasCustomKID  bool
	Parameters    *Parameters
}

// NewPublicKey creates a new JWT ECDSA public key.
//
// The point is expected to be encoded uncompressed as per [SEC 1 v2.0, Section
// 2.3.3].
//
// [SEC 1 v2.0, Section 2.3.3]: https://www.secg.org/sec1-v2.pdf#page=17.08
func NewPublicKey(opts PublicKeyOpts) (*PublicKey, error) {
	if opts.Parameters == nil {
		return nil, fmt.Errorf("jwtecdsa.NewPublicKey: parameters can't be nil")
	}
	if !opts.Parameters.HasIDRequirement() && opts.IDRequirement != 0 {
		return nil, fmt.Errorf("jwtecdsa.NewPublicKey: ID requirement must be 0 if ID is not required")
	}
	curve, err := ecdhCurveFromAlgorithm(opts.Parameters.Algorithm())
	if err != nil {
		return nil, fmt.Errorf("jwtecdsa.NewPublicKey: %v", err)
	}
	// Validate the point.
	if _, err := curve.NewPublicKey(opts.PublicPoint); err != nil {
		return nil, fmt.Errorf("jwtecdsa.NewPublicKey: point validation failed: %v", err)
	}
	kid, hasKID, err := computeKID(opts.CustomKID, opts.HasCustomKID, opts.IDRequirement, opts.Parameters)
	if err != nil {
		return nil, fmt.Errorf("jwtecdsa.NewPublicKey: %v", err)
	}
	return &PublicKey{
		parameters:    opts.Parameters,
		publicPoint:   opts.PublicPoint,
		idRequirement: opts.IDRequirement,
		kid:           kid,
		hasKID:        hasKID,
	}, nil
}

// Parameters returns the parameters of the key.
func (k *PublicKey) Parameters() key.Parameters { return k.parameters }

// PublicPoint returns the public key uncompressed point.
//
// Point format as per [SEC 1 v2.0, Section 2.3.3].
//
// [SEC 1 v2.0, Section 2.3.3]: https://www.secg.org/sec1-v2.pdf#page=17.08
func (k *PublicKey) PublicPoint() []byte { return k.publicPoint }

// KID returns the KID for this key.
//
// If no kid is set, it returns ("", false).
func (k *PublicKey) KID() (string, bool) { return k.kid, k.hasKID }

// IDRequirement returns the ID requirement for this key.
func (k *PublicKey) IDRequirement() (uint32, bool) {
	return k.idRequirement, k.parameters.HasIDRequirement()
}

// Equal returns true if k and other are equal.
func (k *PublicKey) Equal(other key.Key) bool {
	that, ok := other.(*PublicKey)
	return ok && k.parameters.Equal(that.parameters) &&
		bytes.Equal(k.publicPoint, that.publicPoint) &&
		k.idRequirement == that.idRequirement &&
		k.kid == that.kid && k.hasKID == that.hasKID
}
