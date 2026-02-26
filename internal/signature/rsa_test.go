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
	"bytes"
	"math/big"
	"testing"

	internal "github.com/tink-crypto/tink-go/v2/internal/signature"
)

func TestPad(t *testing.T) {
	tests := []struct {
		name           string
		toPad          []byte
		encodingLength int
		want           []byte
		wantErr        bool
	}{
		{
			name:           "padding needed",
			toPad:          []byte{1, 2, 3},
			encodingLength: 5,
			want:           []byte{0, 0, 1, 2, 3},
			wantErr:        false,
		},
		{
			name:           "no padding needed",
			toPad:          []byte{1, 2, 3, 4, 5},
			encodingLength: 5,
			want:           []byte{1, 2, 3, 4, 5},
			wantErr:        false,
		},
		{
			name:           "toPad is too long",
			toPad:          []byte{1, 2, 3},
			encodingLength: 2,
			want:           nil,
			wantErr:        true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := internal.Pad(tc.toPad, tc.encodingLength)
			if tc.wantErr {
				if err == nil {
					t.Errorf("Pad(%v, %d) err = nil, want error", tc.toPad, tc.encodingLength)
				}
				return
			}
			if err != nil {
				t.Fatalf("Pad(%v, %d) err = %v, want nil", tc.toPad, tc.encodingLength, err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Errorf("Pad(%v, %d) = %v, want %v", tc.toPad, tc.encodingLength, got, tc.want)
			}
		})
	}
}

func TestAdjustEncodingLengths(t *testing.T) {
	tests := []struct {
		name    string
		n       string
		p       string
		q       string
		d       string
		dp      string
		dq      string
		crt     string
		wantErr bool
		wantD   string
		wantDp  string
		wantDq  string
		wantCrt string
	}{
		{
			name:    "padding needed",
			n:       "aabbccddeeff00112233445566778899",
			p:       "aabbccddeeff0011",
			q:       "2233445566778899",
			d:       "112233",
			dp:      "445566",
			dq:      "778899",
			crt:     "aabbcc",
			wantErr: false,
			wantD:   "00000000000000000000000000112233",
			wantDp:  "0000000000445566",
			wantDq:  "0000000000778899",
			wantCrt: "0000000000aabbcc",
		},
		{
			name:    "no padding needed",
			n:       "aabbccddeeff00112233445566778899",
			p:       "aabbccddeeff0011",
			q:       "2233445566778899",
			d:       "11223344556677881122334455667788",
			dp:      "1122334455667788",
			dq:      "1122334455667788",
			crt:     "1122334455667788",
			wantErr: false,
			wantD:   "11223344556677881122334455667788",
			wantDp:  "1122334455667788",
			wantDq:  "1122334455667788",
			wantCrt: "1122334455667788",
		},
		{
			name:    "dp too long",
			n:       "aabbccddeeff00112233445566778899",
			p:       "aabbccddeeff0011",
			q:       "2233445566778899",
			d:       "112233",
			dp:      "112233445566778899", // Too long
			dq:      "778899",
			crt:     "aabbcc",
			wantErr: true,
		},
		{
			name:    "dq too long",
			n:       "aabbccddeeff00112233445566778899",
			p:       "aabbccddeeff0011",
			q:       "2233445566778899",
			d:       "112233",
			dp:      "445566",
			dq:      "112233445566778899", // Too long
			crt:     "aabbcc",
			wantErr: true,
		},
		{
			name:    "crt too long",
			n:       "aabbccddeeff00112233445566778899",
			p:       "aabbccddeeff0011",
			q:       "2233445566778899",
			d:       "112233",
			dp:      "445566",
			dq:      "778899",
			crt:     "112233445566778899", // Too long
			wantErr: true,
		},
		{
			name:    "d too long",
			n:       "aabbccddeeff0011",
			p:       "aabbccddeeff0011",
			q:       "2233445566778899",
			d:       "112233445566778899", // Too long
			dp:      "445566",
			dq:      "778899",
			crt:     "aabbcc",
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			n := hexDecode(t, test.n)
			p := hexDecode(t, test.p)
			q := hexDecode(t, test.q)
			d := hexDecode(t, test.d)
			dp := hexDecode(t, test.dp)
			dq := hexDecode(t, test.dq)
			crt := hexDecode(t, test.crt)

			adjD, adjDp, adjDq, adjCrt, err := internal.AdjustEncodingLengths(n, p, q, d, dp, dq, crt)

			if test.wantErr {
				if err == nil {
					t.Errorf("AdjustEncodingLengths() err = nil, want error")
				}
				return
			}

			if err != nil {
				t.Fatalf("AdjustEncodingLengths() err = %v, want nil", err)
			}

			if got, want := adjD, hexDecode(t, test.wantD); !bytes.Equal(got, want) {
				t.Errorf("d = %x, want %x", got, want)
			}
			if got, want := adjDp, hexDecode(t, test.wantDp); !bytes.Equal(got, want) {
				t.Errorf("dp = %x, want %x", got, want)
			}
			if got, want := adjDq, hexDecode(t, test.wantDq); !bytes.Equal(got, want) {
				t.Errorf("dq = %x, want %x", got, want)
			}
			if got, want := adjCrt, hexDecode(t, test.wantCrt); !bytes.Equal(got, want) {
				t.Errorf("crt = %x, want %x", got, want)
			}
		})
	}
}

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
