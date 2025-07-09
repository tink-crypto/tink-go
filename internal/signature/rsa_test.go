// Copyright 2022 Google LLC
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

package signature_test

import (
	"math/big"
	"testing"

	internal "github.com/tink-crypto/tink-go/v2/internal/signature"
)

func TestValidatePublicExponent(t *testing.T) {
	if err := internal.RSAValidPublicExponent(65537); err != nil {
		t.Errorf("ValidPublicExponent(65537) err = %v, want nil", err)
	}
}

func TestValidateInvalidPublicExponentFails(t *testing.T) {
	if err := internal.RSAValidPublicExponent(3); err == nil {
		t.Errorf("ValidPublicExponent(3) err = nil, want error")
	}
}

func TestValidateModulusSizeInBits(t *testing.T) {
	if err := internal.RSAValidModulusSizeInBits(2048); err != nil {
		t.Errorf("ValidModulusSizeInBits(2048) err = %v, want nil", err)
	}
}

func TestValidateInvalidModulusSizeInBitsFails(t *testing.T) {
	if err := internal.RSAValidModulusSizeInBits(1024); err == nil {
		t.Errorf("ValidModulusSizeInBits(1024) err = nil, want error")
	}
}

func TestHashSafeForSignature(t *testing.T) {
	for _, h := range []string{
		"SHA256",
		"SHA384",
		"SHA512",
	} {
		t.Run(h, func(t *testing.T) {
			if err := internal.HashSafeForSignature(h); err != nil {
				t.Errorf("HashSafeForSignature(%q)  err = %v, want nil", h, err)
			}
		})
	}
}

func TestHashNotSafeForSignatureFails(t *testing.T) {
	for _, h := range []string{
		"SHA1",
		"SHA224",
		"MD5",
	} {
		t.Run(h, func(t *testing.T) {
			if err := internal.HashSafeForSignature(h); err == nil {
				t.Errorf("HashSafeForSignature(%q)  err = nil, want error", h)
			}
		})
	}
}

func TestValidateRSAPublicKeyParams(t *testing.T) {
	f4 := new(big.Int).SetInt64(65537).Bytes()
	invalidPubExponent := new(big.Int).SetInt64(65537 + 1).Bytes()
	publicExponentTooLarge := make([]byte, 65)
	publicExponentTooLarge[0] = 0xff
	for _, tc := range []struct {
		name            string
		hashType        string
		modulusSizeBits int
		pubExponent     []byte
		wantErr         bool
	}{
		{
			name:            "valid",
			hashType:        "SHA256",
			modulusSizeBits: 2048,
			pubExponent:     f4,
			wantErr:         false,
		},
		{
			name:            "hash unsafe for signature",
			hashType:        "SHA1",
			modulusSizeBits: 2048,
			pubExponent:     f4,
			wantErr:         true,
		},
		{
			name:            "modulus size too small",
			hashType:        "SHA256",
			modulusSizeBits: 1024,
			pubExponent:     f4,
			wantErr:         true,
		},
		{
			name:            "public exponent not F4",
			hashType:        "SHA256",
			modulusSizeBits: 2048,
			pubExponent:     invalidPubExponent,
			wantErr:         true,
		},
		{
			name:            "public exponent too large",
			hashType:        "SHA256",
			modulusSizeBits: 2048,
			pubExponent:     publicExponentTooLarge,
			wantErr:         true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := internal.ValidateRSAPublicKeyParams(tc.hashType, tc.modulusSizeBits, tc.pubExponent)
			if tc.wantErr && err == nil {
				t.Errorf("ValidateRSAPublicKeyParams(%v, %v, %v) err = nil, want error", tc.hashType, tc.modulusSizeBits, tc.pubExponent)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidateRSAPublicKeyParams(%v, %v, %v) err = %v, want nil", tc.hashType, tc.modulusSizeBits, tc.pubExponent, err)
			}
		})
	}
}
