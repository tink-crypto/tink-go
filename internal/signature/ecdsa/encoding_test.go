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

package ecdsa_test

import (
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/internal/signature/ecdsa"
)

func hexToBytes(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) err = %v, want nil", h, err)
	}
	return b
}

func TestASN1Encode(t *testing.T) {
	for _, tc := range []struct {
		name   string
		rHex   string
		sHex   string
		derHex string
	}{
		{
			name:   "short form length",
			rHex:   "0102030405060708090a0b0c0d0e0f10",
			sHex:   "1102030405060708090a0b0c0d0e0fff",
			derHex: "302402100102030405060708090a0b0c0d0e0f1002101102030405060708090a0b0c0d0e0fff",
		},
		{
			name:   "long form length",
			rHex:   "010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000203",
			sHex:   "0f0000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000204",
			derHex: "308188024201000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000020302420f0000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000204",
		},
		{
			name:   "zero prefix",
			rHex:   "02030405060708090a0b0c0d0e0f10",
			sHex:   "02030405060708090a0b0c0d0e0f10",
			derHex: "3022020f02030405060708090a0b0c0d0e0f10020f02030405060708090a0b0c0d0e0f10",
		},
		{
			name:   "highest bit set - long form length",
			rHex:   "ff02030405060708090a0b0c0d0e0f10",
			sHex:   "ff02030405060708090a0b0c0d0e0f10",
			derHex: "3026021100ff02030405060708090a0b0c0d0e0f10021100ff02030405060708090a0b0c0d0e0f10",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &ecdsa.Signature{R: new(big.Int).SetBytes(hexToBytes(t, tc.rHex)), S: new(big.Int).SetBytes(hexToBytes(t, tc.sHex))}
			got, err := ecdsa.ASN1Encode(s)
			if err != nil {
				t.Fatalf("ecdsa.ASN1Encode(%v) err = %v, want nil", s, err)
			}
			if diff := cmp.Diff(hexToBytes(t, tc.derHex), got); diff != "" {
				t.Errorf("ecdsa.ASN1Encode(%v) returned unexpected diff (-want +got):\n%s", s, diff)
			}
		})
	}
}

func TestASN1EncodeFails(t *testing.T) {
	s := &ecdsa.Signature{}
	if _, err := ecdsa.ASN1Encode(s); err == nil {
		t.Fatalf("ecdsa.ASN1Encode(%v) err = nil, want error", s)
	}
}

func TestASN1Decode(t *testing.T) {
	s := &ecdsa.Signature{R: big.NewInt(1), S: big.NewInt(2)}
	encoded, err := ecdsa.ASN1Encode(s)
	if err != nil {
		t.Fatalf("ecdsa.ASN1Encode(%v) err = %v, want nil", s, err)
	}
	got, err := ecdsa.ASN1Decode(encoded)
	if err != nil {
		t.Fatalf("ecdsa.ASN1Decode(%v) err = %v, want nil", encoded, err)
	}
	if got.R.Cmp(s.R) != 0 {
		t.Errorf("ecdsa.ASN1Decode(%v).R = %v, want %v", encoded, got.R, s.R)
	}
	if got.S.Cmp(s.S) != 0 {
		t.Errorf("ecdsa.ASN1Decode(%v).S = %v, want %v", encoded, got.S, s.S)
	}
}

func TestASN1DecodeFails(t *testing.T) {
	if _, err := ecdsa.ASN1Decode([]byte("invalid")); err == nil {
		t.Fatalf("ecdsa.ASN1Decode(%v) err = nil, want error", err)
	}
}

func TestIEEEP1363Encode(t *testing.T) {
	// P-256 point.
	p256x := hexToBytes(t, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
	p256y := hexToBytes(t, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
	// P-384 point.
	p384x := hexToBytes(t, "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7")
	p384y := hexToBytes(t, "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f")
	// P-521 point.
	p521x := hexToBytes(t, "c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66")
	p521y := hexToBytes(t, "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650")
	for _, tc := range []struct {
		name string
		s    *ecdsa.Signature
		c    string
		want []byte
	}{
		{
			name: "p256",
			s:    &ecdsa.Signature{R: new(big.Int).SetBytes(p256x), S: new(big.Int).SetBytes(p256y)},
			c:    "P-256",
			want: slices.Concat(p256x, p256y),
		},
		{
			name: "p384",
			s:    &ecdsa.Signature{R: new(big.Int).SetBytes(p384x), S: new(big.Int).SetBytes(p384y)},
			c:    "P-384",
			want: slices.Concat(p384x, p384y),
		},
		{
			name: "p521",
			s:    &ecdsa.Signature{R: new(big.Int).SetBytes(p521x), S: new(big.Int).SetBytes(p521y)},
			c:    "P-521",
			want: slices.Concat([]byte{0x00}, p521x, p521y),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ecdsa.IEEEP1363Encode(tc.s, tc.c)
			if err != nil {
				t.Fatalf("ecdsa.IEEEP1363Encode(%v, %v) err = %v, want nil", tc.s, tc.c, err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ecdsa.IEEEP1363Encode(%v, %v) returned unexpected diff (-want +got):\n%s", tc.s, tc.c, diff)
			}
		})
	}
}

func TestIEEEP1363EncodeFails(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    *ecdsa.Signature
		c    string
	}{
		{
			name: "invalid R",
			s:    &ecdsa.Signature{R: elliptic.P256().Params().Gx, S: new(big.Int).Lsh(big.NewInt(1), 256)},
			c:    "P-256",
		},
		{
			name: "invalid S",
			s:    &ecdsa.Signature{R: new(big.Int).Lsh(big.NewInt(1), 256), S: elliptic.P256().Params().Gy},
			c:    "P-256",
		},
		{
			name: "invalid curve name",
			s:    &ecdsa.Signature{R: elliptic.P256().Params().Gx, S: elliptic.P256().Params().Gy},
			c:    "invalid",
		},
		{
			name: "wrong curve",
			s:    &ecdsa.Signature{R: elliptic.P384().Params().Gx, S: elliptic.P384().Params().Gy},
			c:    "P-256",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ecdsa.IEEEP1363Encode(tc.s, tc.c); err == nil {
				t.Errorf("ecdsa.IEEEP1363Encode(%v, %v) err = nil, want error", tc.s, tc.c)
			}
		})
	}
}

func TestIEEEP1363Decode(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rHex    string
		sHex    string
		ieeeHex string
	}{
		{
			name:    "16 bytes",
			rHex:    "0102030405060708090a0b0c0d0e0f10",
			sHex:    "1102030405060708090a0b0c0d0e0fff",
			ieeeHex: "0102030405060708090a0b0c0d0e0f101102030405060708090a0b0c0d0e0fff",
		},
		{
			name:    "66 bytes",
			rHex:    "010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000203",
			sHex:    "0f0000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000204",
			ieeeHex: "0100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000002030f0000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000204",
		},
		{
			name:    "30 bytes",
			rHex:    "02030405060708090a0b0c0d0e0f10",
			sHex:    "02030405060708090a0b0c0d0e0f10",
			ieeeHex: "02030405060708090a0b0c0d0e0f1002030405060708090a0b0c0d0e0f10",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ecdsa.IEEEP1363Decode(hexToBytes(t, tc.ieeeHex))
			if err != nil {
				t.Fatalf("ecdsa.IEEEP1363Decode(%v) err = %v, want nil", tc.ieeeHex, err)
			}
			if want := new(big.Int).SetBytes(hexToBytes(t, tc.rHex)); got.R.Cmp(want) != 0 {
				t.Errorf("ecdsa.IEEEP1363Decode(%v).R = %v, want %v", tc.ieeeHex, got.R, want)
			}
			if want := new(big.Int).SetBytes(hexToBytes(t, tc.sHex)); got.S.Cmp(want) != 0 {
				t.Errorf("ecdsa.IEEEP1363Decode(%v).S = %v, want %v", tc.ieeeHex, got.S, want)
			}
		})
	}
}

func TestIEEEP1363DecodeFails(t *testing.T) {
	for _, tc := range []struct {
		name    string
		encoded []byte
	}{
		{
			name:    "too small",
			encoded: big.NewInt(1).Bytes(),
		},
		{
			name:    "too large",
			encoded: new(big.Int).Lsh(big.NewInt(1), 132).Bytes(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ecdsa.IEEEP1363Decode(tc.encoded); err == nil {
				t.Fatalf("ecdsa.IEEEP1363Decode(%v) err = nil, want error", tc.encoded)
			}
		})
	}
}
