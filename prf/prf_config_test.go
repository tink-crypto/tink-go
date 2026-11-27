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

package prf_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/config"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveregistry"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/prf/aescmacprf"
	"github.com/tink-crypto/tink-go/v2/prf/hkdfprf"
	"github.com/tink-crypto/tink-go/v2/prf/hmacprf"
	"github.com/tink-crypto/tink-go/v2/prf"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

const (
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/aes_cmac_test.json#L1860
	aesCMACPRFKeyHex        = "e754076ceab3fdaf4f9bcab7d4f0df0cbbafbc87731b8f9b7cd2166472e8eebc"
	aesCMACPRFWantOutputHex = "9d47482c2d9252bace43a75a8335b8b8"
	aesCMACPRFDataHex       = "40"

	// https://datatracker.ietf.org/doc/html/rfc5869#appendix-A.2
	hkdfKeyHex = "000102030405060708090a0b0c0d0e0f" +
		"101112131415161718191a1b1c1d1e1f" +
		"202122232425262728292a2b2c2d2e2f" +
		"303132333435363738393a3b3c3d3e3f" +
		"404142434445464748494a4b4c4d4e4f"
	hkdfSaltHex = "606162636465666768696a6b6c6d6e6f" +
		"707172737475767778797a7b7c7d7e7f" +
		"808182838485868788898a8b8c8d8e8f" +
		"909192939495969798999a9b9c9d9e9f" +
		"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
	hkdfDataHex = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
		"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
		"d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
		"e0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
	hkdfWantOutputHex = "b11e398dc80327a1c8e7f78c596a4934" +
		"4f012eda2d4efad8a050cc4c19afa97c" +
		"59045a99cac7827271cb41c65e590e09" +
		"da3275600c2f09b8367793a9aca3db71" +
		"cc30c58179ec3e87c14c01d5c1f3434f" +
		"1d87"

	// https://github.com/C2SP/wycheproof/blob/3bfb67fca7c7a2ef436e263da53cdabe0fa1dd36/testvectors/hmac_sha256_test.json#L31
	hmacSHA256KeyHex        = "8159fd15133cd964c9a6964c94f0ea269a806fd9f43f0da58b6cd1b33d189b2a"
	hmacSHA256WantOutputHex = "dfc5105d5eecf7ae7b8b8de3930e7659e84c4172f2555142f1e568fc1872ad93"
	hmacSHA256DataHex       = "77"
)

func mustBuildConfig(t *testing.T, register ...func(*config.Builder, internalapi.Token) error) config.Config {
	t.Helper()
	b := config.NewBuilder()
	for _, r := range register {
		if err := r(b, internalapi.Token{}); err != nil {
			t.Fatalf("register() err = %v, want nil", err)
		}
	}
	return b.Build()
}

func TestRegisterPrimitiveConstructors(t *testing.T) {
	aesCMACPRFKeyBytes := mustHexDecode(t, aesCMACPRFKeyHex)
	aesCMACPRFKey, err := aescmacprf.NewKey(secretdata.NewBytesFromData(aesCMACPRFKeyBytes, insecuresecretdataaccess.Token{}))
	if err != nil {
		t.Fatalf("aescmacprf.NewKey(%x) err = %v, want nil", aesCMACPRFKeyBytes, err)
	}

	hkdfKeyBytes := mustHexDecode(t, hkdfKeyHex)
	hkdfSalt := mustHexDecode(t, hkdfSaltHex)
	hkdfParams, err := hkdfprf.NewParameters(len(hkdfKeyBytes), hkdfprf.SHA256, hkdfSalt)
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters(%d, %v, %x) err = %v, want nil", len(hkdfKeyBytes), hkdfprf.SHA256, hkdfSalt, err)
	}
	hkdfKey, err := hkdfprf.NewKey(secretdata.NewBytesFromData(hkdfKeyBytes, insecuresecretdataaccess.Token{}), hkdfParams)
	if err != nil {
		t.Fatalf("hkdfprf.NewKey(%x, %v) err = %v, want nil", hkdfKeyBytes, hkdfParams, err)
	}

	hmacSHA256KeyBytes := mustHexDecode(t, hmacSHA256KeyHex)
	hmacSHA256Params, err := hmacprf.NewParameters(len(hmacSHA256KeyBytes), hmacprf.SHA256)
	if err != nil {
		t.Fatalf("hmacprf.NewParameters(%d, %v) err = %v, want nil", len(hmacSHA256KeyBytes), hmacprf.SHA256, err)
	}
	hmacSHA256Key, err := hmacprf.NewKey(secretdata.NewBytesFromData(hmacSHA256KeyBytes, insecuresecretdataaccess.Token{}), hmacSHA256Params)
	if err != nil {
		t.Fatalf("hmacprf.NewKey(%x, %v) err = %v, want nil", hmacSHA256KeyBytes, hmacSHA256Params, err)
	}

	tests := []struct {
		name     string
		register func(*config.Builder, internalapi.Token) error
		key      key.Key
		data     []byte
		want     []byte
	}{
		{
			name:     "AESCMACPRF",
			register: prf.RegisterAESCMACPRFPrimitiveConstructor,
			key:      aesCMACPRFKey,
			data:     mustHexDecode(t, aesCMACPRFDataHex),
			want:     mustHexDecode(t, aesCMACPRFWantOutputHex),
		},
		{
			name:     "HKDFPRF",
			register: prf.RegisterHKDFPRFPrimitiveConstructor,
			key:      hkdfKey,
			data:     mustHexDecode(t, hkdfDataHex),
			want:     mustHexDecode(t, hkdfWantOutputHex),
		},
		{
			name:     "HMACPRF",
			register: prf.RegisterHMACPRFPrimitiveConstructor,
			key:      hmacSHA256Key,
			data:     mustHexDecode(t, hmacSHA256DataHex),
			want:     mustHexDecode(t, hmacSHA256WantOutputHex),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			configWithout := mustBuildConfig(t)
			if _, err := configWithout.PrimitiveFromKey(tc.key, internalapi.Token{}); err == nil {
				t.Fatalf("configWithout.PrimitiveFromKey(%T) err = nil, want error", tc.key)
			}
			configWith := mustBuildConfig(t, tc.register)
			primitive, err := configWith.PrimitiveFromKey(tc.key, internalapi.Token{})
			if err != nil {
				t.Fatalf("configWith.PrimitiveFromKey(%T) err = %v, want nil", tc.key, err)
			}
			p, ok := primitive.(prf.PRF)
			if !ok {
				t.Fatalf("configWith.PrimitiveFromKey(%T) returned type %T, want prf.PRF", tc.key, primitive)
			}
			got, err := p.ComputePRF(tc.data, uint32(len(tc.want)))
			if err != nil {
				t.Fatalf("p.ComputePRF(%x, %d) err = %v, want nil", tc.data, len(tc.want), err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Errorf("p.ComputePRF(%x, %d) = %x, want %x", tc.data, len(tc.want), got, tc.want)
			}
		})
	}
}

func TestRegisterPrimitiveConstructorPrimitivesFromGlobalRegistry(t *testing.T) {
	aesCMACPRFKeyBytes := mustHexDecode(t, aesCMACPRFKeyHex)
	aesCMACPRFKey, err := aescmacprf.NewKey(secretdata.NewBytesFromData(aesCMACPRFKeyBytes, insecuresecretdataaccess.Token{}))
	if err != nil {
		t.Fatalf("aescmacprf.NewKey(%x) err = %v, want nil", aesCMACPRFKeyBytes, err)
	}

	hkdfKeyBytes := mustHexDecode(t, hkdfKeyHex)
	hkdfSalt := mustHexDecode(t, hkdfSaltHex)
	hkdfParams, err := hkdfprf.NewParameters(len(hkdfKeyBytes), hkdfprf.SHA256, hkdfSalt)
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters(%d, %v, %x) err = %v, want nil", len(hkdfKeyBytes), hkdfprf.SHA256, hkdfSalt, err)
	}
	hkdfKey, err := hkdfprf.NewKey(secretdata.NewBytesFromData(hkdfKeyBytes, insecuresecretdataaccess.Token{}), hkdfParams)
	if err != nil {
		t.Fatalf("hkdfprf.NewKey(%x, %v) err = %v, want nil", hkdfKeyBytes, hkdfParams, err)
	}

	hmacSHA256KeyBytes := mustHexDecode(t, hmacSHA256KeyHex)
	hmacSHA256Params, err := hmacprf.NewParameters(len(hmacSHA256KeyBytes), hmacprf.SHA256)
	if err != nil {
		t.Fatalf("hmacprf.NewParameters(%d, %v) err = %v, want nil", len(hmacSHA256KeyBytes), hmacprf.SHA256, err)
	}
	hmacSHA256Key, err := hmacprf.NewKey(secretdata.NewBytesFromData(hmacSHA256KeyBytes, insecuresecretdataaccess.Token{}), hmacSHA256Params)
	if err != nil {
		t.Fatalf("hmacprf.NewKey(%x, %v) err = %v, want nil", hmacSHA256KeyBytes, hmacSHA256Params, err)
	}

	tests := []struct {
		name string
		key  key.Key
		data []byte
		want []byte
	}{
		{
			name: "AESCMACPRF",
			key:  aesCMACPRFKey,
			data: mustHexDecode(t, aesCMACPRFDataHex),
			want: mustHexDecode(t, aesCMACPRFWantOutputHex),
		},
		{
			name: "HKDFPRF",
			key:  hkdfKey,
			data: mustHexDecode(t, hkdfDataHex),
			want: mustHexDecode(t, hkdfWantOutputHex),
		},
		{
			name: "HMACPRF",
			key:  hmacSHA256Key,
			data: mustHexDecode(t, hmacSHA256DataHex),
			want: mustHexDecode(t, hmacSHA256WantOutputHex),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			primitive, err := primitiveregistry.Primitive(tc.key)
			if err != nil {
				t.Fatalf("primitiveregistry.Primitive(%T) err = %v, want nil", tc.key, err)
			}
			p, ok := primitive.(prf.PRF)
			if !ok {
				t.Fatalf("primitiveregistry.Primitive(%T) returned type %T, want prf.PRF", tc.key, primitive)
			}
			got, err := p.ComputePRF(tc.data, uint32(len(tc.want)))
			if err != nil {
				t.Fatalf("p.ComputePRF(%x, %d) err = %v, want nil", tc.data, len(tc.want), err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Errorf("p.ComputePRF(%x, %d) = %x, want %x", tc.data, len(tc.want), got, tc.want)
			}
		})
	}
}

func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) err = %v, want nil", s, err)
	}
	return b
}
