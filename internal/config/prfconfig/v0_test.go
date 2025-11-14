// Copyright 2025 Google LLC
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

package prfconfig_test

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/config/prfconfig"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/prf/aescmacprf"
	"github.com/tink-crypto/tink-go/v2/prf/hkdfprf"
	"github.com/tink-crypto/tink-go/v2/prf/hmacprf"
	"github.com/tink-crypto/tink-go/v2/prf"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

func TestConfigV0FailsIfKeyNotPRF(t *testing.T) {
	configV0 := prfconfig.V0()
	aesGCMParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantNoPrefix,
		IVSizeInBytes:  12,
	})
	if err != nil {
		t.Fatalf("aescmac.NewParameters() err = %v, want nil", err)
	}
	aesGCMKey, err := aesgcm.NewKey(secretdata.NewBytesFromData([]byte("01234567890123456789012345678901"), insecuresecretdataaccess.Token{}), 0, aesGCMParams)
	if err != nil {
		t.Fatalf(" aescmac.NewKey() err = %v, want nil", err)
	}
	if _, err := configV0.PrimitiveFromKey(aesGCMKey, internalapi.Token{}); err == nil {
		t.Errorf("configV0.PrimitiveFromKey() err = nil, want error")
	}
}

const (
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

	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/aes_cmac_test.json#L1860
	aesCMACPRFKeyHex        = "e754076ceab3fdaf4f9bcab7d4f0df0cbbafbc87731b8f9b7cd2166472e8eebc"
	aesCMACPRFWantOutputHex = "9d47482c2d9252bace43a75a8335b8b8"
	aesCMACPRFDataHex       = "40"

	// https://github.com/C2SP/wycheproof/blob/3bfb67fca7c7a2ef436e263da53cdabe0fa1dd36/testvectors/hmac_sha256_test.json#L31
	hmacSHA256KeyHex        = "8159fd15133cd964c9a6964c94f0ea269a806fd9f43f0da58b6cd1b33d189b2a"
	hmacSHA256WantOutputHex = "dfc5105d5eecf7ae7b8b8de3930e7659e84c4172f2555142f1e568fc1872ad93"
	hmacSHA256DataHex       = "77"
)

func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("failed to decode hex string %q: %v", s, err)
	}
	return b
}

func TestConfigV0WithPRFKeys(t *testing.T) {
	configV0 := prfconfig.V0()

	aesCMACPRFKeyBytes := mustHexDecode(t, aesCMACPRFKeyHex)
	aesCMACPRFKey, err := aescmacprf.NewKey(secretdata.NewBytesFromData(aesCMACPRFKeyBytes, insecuresecretdataaccess.Token{}))
	if err != nil {
		t.Fatalf("keygenregistry.CreateKey() err = %v, want nil", err)
	}

	hkdfKeyBytes := mustHexDecode(t, hkdfKeyHex)
	hkdfprfParams, err := hkdfprf.NewParameters(len(hkdfKeyBytes), hkdfprf.SHA256, mustHexDecode(t, hkdfSaltHex))
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters() err = %v, want nil", err)
	}
	hkdfprfKey, err := hkdfprf.NewKey(secretdata.NewBytesFromData(hkdfKeyBytes, insecuresecretdataaccess.Token{}), hkdfprfParams)
	if err != nil {
		t.Fatalf("keygenregistry.CreateKey() err = %v, want nil", err)
	}

	hmacSHA256KeyBytes := mustHexDecode(t, hmacSHA256KeyHex)
	hmacSHA256PRFParams, err := hmacprf.NewParameters(len(hmacSHA256KeyBytes), hmacprf.SHA256)
	if err != nil {
		t.Fatalf("hmacprf.NewParameters() err = %v, want nil", err)
	}
	hmacSHA256PRFKey, err := hmacprf.NewKey(secretdata.NewBytesFromData(hmacSHA256KeyBytes, insecuresecretdataaccess.Token{}), hmacSHA256PRFParams)
	if err != nil {
		t.Fatalf("hmacprf.NewKey() err = %v, want nil", err)
	}

	for _, test := range []struct {
		name string
		key  key.Key
		data []byte
		want []byte
	}{
		{
			name: "AES-CMAC-PRF",
			key:  aesCMACPRFKey,
			data: mustHexDecode(t, aesCMACPRFDataHex),
			want: mustHexDecode(t, aesCMACPRFWantOutputHex),
		},
		{
			name: "HKDF-PRF",
			key:  hkdfprfKey,
			data: mustHexDecode(t, hkdfDataHex),
			want: mustHexDecode(t, hkdfWantOutputHex),
		},
		{
			name: "HMAC-PRF",
			key:  hmacSHA256PRFKey,
			data: mustHexDecode(t, hmacSHA256DataHex),
			want: mustHexDecode(t, hmacSHA256WantOutputHex),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			primitive, err := configV0.PrimitiveFromKey(test.key, internalapi.Token{})
			if err != nil {
				t.Fatalf("configV0.PrimitiveFromKey() err = %v, want nil", err)
			}
			p, ok := primitive.(prf.PRF)
			if !ok {
				t.Fatalf("primitive is of type %v, want prf.Set", reflect.TypeOf(primitive))
			}

			output, err := p.ComputePRF(test.data, uint32(len(test.want)))
			if err != nil {
				t.Fatalf("p.ComputePRF() err = %v, want nil", err)
			}
			if !bytes.Equal(output, test.want) {
				t.Errorf("p.ComputePRF() output = %x, want %x", output, test.want)
			}
		})
	}
}
