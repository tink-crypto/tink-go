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
	"github.com/tink-crypto/tink-go/v2/prf"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

const (
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/aes_cmac_test.json#L1860
	aesCMACPRFKeyHex        = "e754076ceab3fdaf4f9bcab7d4f0df0cbbafbc87731b8f9b7cd2166472e8eebc"
	aesCMACPRFWantOutputHex = "9d47482c2d9252bace43a75a8335b8b8"
	aesCMACPRFDataHex       = "40"
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
		t.Fatalf("aescmacprf.NewKey() err = %v, want nil", err)
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
		t.Fatalf("aescmacprf.NewKey() err = %v, want nil", err)
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
