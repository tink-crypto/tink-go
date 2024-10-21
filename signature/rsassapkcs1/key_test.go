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

package rsassapkcs1_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"

	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapkcs1"
)

const (
	f4 = 65537
)

func TestNewParametersInvalidValues(t *testing.T) {
	testCases := []struct {
		name            string
		modulusSizeBits int
		hashType        rsassapkcs1.HashType
		publicExponent  int
		variant         rsassapkcs1.Variant
	}{
		{
			name:            "small public exponent",
			modulusSizeBits: 2048,
			hashType:        rsassapkcs1.SHA256,
			publicExponent:  f4 - 1,
			variant:         rsassapkcs1.VariantTink,
		},
		{
			name:            "large public exponent",
			modulusSizeBits: 2048,
			hashType:        rsassapkcs1.SHA256,
			publicExponent:  1 << 31,
			variant:         rsassapkcs1.VariantTink,
		},
		{
			name:            "even public exponent",
			modulusSizeBits: 2048,
			hashType:        rsassapkcs1.SHA256,
			publicExponent:  f4 + 1,
			variant:         rsassapkcs1.VariantTink,
		},
		{
			name:            "unknown hash",
			modulusSizeBits: 2048,
			hashType:        rsassapkcs1.UnknownHashType,
			publicExponent:  f4,
			variant:         rsassapkcs1.VariantTink,
		},
		{
			name:            "unknown variant",
			modulusSizeBits: 2048,
			hashType:        rsassapkcs1.SHA256,
			publicExponent:  f4,
			variant:         rsassapkcs1.VariantUnknown,
		},
		{
			name:            "invalid modulus size (too small)",
			modulusSizeBits: 1024,
			hashType:        rsassapkcs1.SHA256,
			publicExponent:  f4,
			variant:         rsassapkcs1.VariantTink,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := rsassapkcs1.NewParameters(tc.modulusSizeBits, tc.hashType, tc.publicExponent, tc.variant); err == nil {
				t.Errorf("rsassapkcs1.NewParameters(%v, %v, %v, %v) = nil, want error", tc.modulusSizeBits, tc.hashType, tc.publicExponent, tc.variant)
			}
		})
	}
}

func TestNewParameters(t *testing.T) {
	for _, hashType := range []rsassapkcs1.HashType{rsassapkcs1.SHA256, rsassapkcs1.SHA384, rsassapkcs1.SHA512} {
		for _, variant := range []rsassapkcs1.Variant{rsassapkcs1.VariantTink, rsassapkcs1.VariantCrunchy, rsassapkcs1.VariantLegacy, rsassapkcs1.VariantNoPrefix} {
			for _, modulusSizeBits := range []int{2048, 3072, 4096} {
				for _, publicExponent := range []int{f4, 1<<31 - 1} {
					t.Run(fmt.Sprintf("modulusSizeBits:%v_hashType:%v_publicExponent:%v_variant:%v", modulusSizeBits, hashType, publicExponent, variant), func(t *testing.T) {
						params, err := rsassapkcs1.NewParameters(modulusSizeBits, hashType, publicExponent, variant)
						if err != nil {
							t.Fatalf("rsassapkcs1.NewParameters(%v, %v, %v, %v) = %v, want nil", modulusSizeBits, hashType, publicExponent, variant, err)
						}
						if got, want := params.ModulusSizeBits(), modulusSizeBits; got != want {
							t.Errorf("params.ModulusSizeBits() = %v, want %v", got, want)
						}
						if got, want := params.HashType(), hashType; got != want {
							t.Errorf("params.HashType() = %v, want %v", got, want)
						}
						if got, want := params.PublicExponent(), publicExponent; got != want {
							t.Errorf("params.PublicExponent() = %v, want %v", got, want)
						}
						if got, want := params.Variant(), variant; got != want {
							t.Errorf("params.Variant() = %v, want %v", got, want)
						}
						if got, want := params.HasIDRequirement(), variant != rsassapkcs1.VariantNoPrefix; got != want {
							t.Errorf("params.HasIDRequirement() = %v, want %v", got, want)
						}
						other, err := rsassapkcs1.NewParameters(modulusSizeBits, hashType, publicExponent, variant)
						if err != nil {
							t.Fatalf("rsassapkcs1.NewParameters(%v, %v, %v, %v) = %v, want nil", modulusSizeBits, hashType, publicExponent, variant, err)
						}
						if !params.Equals(other) {
							t.Errorf("params.Equals(other) = false, want true")
						}
					})
				}
			}
		}
	}
}

type testParams struct {
	modulusSizeBits int
	hashType        rsassapkcs1.HashType
	publicExponent  int
	variant         rsassapkcs1.Variant
}

func TestNewParametersDifferentParameters(t *testing.T) {
	for _, tc := range []struct {
		name string
		this testParams
		that testParams
	}{
		{
			name: "different modulus size",
			this: testParams{
				modulusSizeBits: 2048,
				hashType:        rsassapkcs1.SHA256,
				publicExponent:  f4,
				variant:         rsassapkcs1.VariantTink,
			},
			that: testParams{
				modulusSizeBits: 3072,
				hashType:        rsassapkcs1.SHA256,
				publicExponent:  f4,
				variant:         rsassapkcs1.VariantTink,
			},
		},
		{
			name: "different hash type",
			this: testParams{
				modulusSizeBits: 2048,
				hashType:        rsassapkcs1.SHA256,
				publicExponent:  f4,
				variant:         rsassapkcs1.VariantTink,
			},
			that: testParams{
				modulusSizeBits: 2048,
				hashType:        rsassapkcs1.SHA384,
				publicExponent:  f4,
				variant:         rsassapkcs1.VariantTink,
			},
		},
		{
			name: "different public exponent",
			this: testParams{
				modulusSizeBits: 2048,
				hashType:        rsassapkcs1.SHA256,
				publicExponent:  f4,
				variant:         rsassapkcs1.VariantTink,
			},
			that: testParams{
				modulusSizeBits: 2048,
				hashType:        rsassapkcs1.SHA256,
				publicExponent:  1<<31 - 1,
				variant:         rsassapkcs1.VariantTink,
			},
		},
		{
			name: "different variant",
			this: testParams{
				modulusSizeBits: 2048,
				hashType:        rsassapkcs1.SHA256,
				publicExponent:  f4,
				variant:         rsassapkcs1.VariantTink,
			},
			that: testParams{
				modulusSizeBits: 2048,
				hashType:        rsassapkcs1.SHA256,
				publicExponent:  1<<31 - 1,
				variant:         rsassapkcs1.VariantNoPrefix,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			this, err := rsassapkcs1.NewParameters(tc.this.modulusSizeBits, tc.this.hashType, tc.this.publicExponent, tc.this.variant)
			if err != nil {
				t.Fatalf("rsassapkcs1.NewParameters(%v, %v, %v, %v) = %v, want nil", tc.this.modulusSizeBits, tc.this.hashType, tc.this.publicExponent, tc.this.variant, err)
			}
			that, err := rsassapkcs1.NewParameters(tc.that.modulusSizeBits, tc.that.hashType, tc.that.publicExponent, tc.that.variant)
			if err != nil {
				t.Fatalf("rsassapkcs1.NewParameters(%v, %v, %v, %v) = %v, want nil", tc.that.modulusSizeBits, tc.that.hashType, tc.that.publicExponent, tc.that.variant, err)
			}
			if this.Equals(that) {
				t.Errorf("this.Equals(that) = true, want false")
			}
		})
	}
}

const (
	// Taken from:
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/rsa_pkcs1_2048_test.json#L13
	n2048Base64 = "s1EKK81M5kTFtZSuUFnhKy8FS2WNXaWVmi_fGHG4CLw98-Yo0nkuUarVwSS0O9pFPcpc3kvPKOe9Tv-6DLS3Qru21aATy2PRqjqJ4CYn71OYtSwM_ZfSCKvrjXybzgu-sBmobdtYm-sppbdL-GEHXGd8gdQw8DDCZSR6-dPJFAzLZTCdB-Ctwe_RXPF-ewVdfaOGjkZIzDoYDw7n-OHnsYCYozkbTOcWHpjVevipR-IBpGPi1rvKgFnlcG6d_tj0hWRl_6cS7RqhjoiNEtxqoJzpXs_Kg8xbCxXbCchkf11STA8udiCjQWuWI8rcDwl69XMmHJjIQAqhKvOOQ8rYTQ"

	// Taken from:
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/rsa_pkcs1_3072_test.json#L21
	n3072Base64 = "3I94gGcvDPnWNheopYvdJxoQm63aD6gm-UuKeVUmtqSagFZMyrqKlJGpNaU-3q4dmntUY9ni7z7gznv_XUtsgUe1wHPC8iBRXVMdVaNmh6bePDR3XC8VGRrAp0LXNCIoyNkQ_mu8pDlTnEhd68vQ7g5LrjF1A7g87oEArHu0WHRny8Q3PEvaLu33xBYx5QkitYD1vOgdJLIIyrzS11_P6Z91tJPf_Fyb2ZD3_Dvy7-OS_srjbz5O9EVsG13pnMdFFzOpELaDS2HsKSdNmGvjdSw1CxOjJ9q8CN_PZWVJmtJuhTRGYz6tspcMqVvPa_Bf_bwqgEN412mFpx8G-Ql5-f73FsNqpiWkW17t9QglpT6dlDWyPKq55cZNOP06dn4YWtdyfW4V-em6svQYTWSHaV25ommMZysugjQQ2-8dk_5AydNX7p_Hf4Sd4RNj9YOvjM9Rgcoa65RMQiUWy0AelQkj5L2IFDn6EJPHdYK_4axZk2dHALZDQzngJFMV2G_L"

	// Taken from:
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/rsa_pkcs1_4096_test.json#L21
	n4096Base64 = "9gG-DczQSqQLEvPxka4XwfnIwLaOenfhS-JcPHkHyx0zpu9BjvQYUvMsmDkrxcmu2RwaFQHFA-q4mz7m9PjrLg_PxBvQNgnPao6zqm8PviMYezPbTTS2bRKKiroKKr9Au50T2OJVRWmlerHYxhuMrS3IhZmuDaU0bhXazhuse_aXN8IvCDvptGu4seq1lXstp0AnXpbIcZW5b-EUUhWdr8_ZFs7l10mne8OQWl69OHrkRej-cPFumghmOXec7_v9QVV72Zrqajcaa0sWBhWhoSvGlY00vODIWty9g5L6EM7KUiCdVhlro9JzziKPHxERkqqS3ioDl5ihe87LTcYQDm-K6MJkPyrnaLIlXwgsl46VylUVVfEGCCMc-AA7v4B5af_x5RkUuajJuPRWRkW55dcF_60pZj9drj12ZStCLkPxPmwUkQkIBcLRJop0olEXdCfjOpqRF1w2cLkXRgCLzh_SMebk8q1wy0OspfB2AKbTHdApFSQ9_dlDoCFl2jZ6a35Nrh3S6Lg2kDCAeV0lhQdswcFd2ejS5eBHUmVpsb_TldlX65_eMl00LRRCbnHv3BiHUV5TzepYNJIfkoYp50ju0JesQCTivyVdcEEfhzc5SM-Oiqfv-isKtH1RZgkeGu3sYFaLFVvZwnvFXz7ONfg9Y2281av0hToFHblNUEU"
)

func base64Decode(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(value)
	if err != nil {
		t.Fatalf("base64 decoding failed: %v", err)
	}
	return decoded
}

func TestNewPublicKeyInvalidValues(t *testing.T) {
	modulus2048 := base64Decode(t, n2048Base64)
	tinkParams, err := rsassapkcs1.NewParameters(2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantTink)
	if err != nil {
		t.Fatalf("rsassapkcs1.NewParameters(%v, %v, %v) = %v, want nil", 2048, rsassapkcs1.SHA256, rsassapkcs1.VariantTink, err)
	}
	noPrefixParams, err := rsassapkcs1.NewParameters(2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantNoPrefix)
	if err != nil {
		t.Fatalf("rsassapkcs1.NewParameters(%v, %v, %v) = %v, want nil", 2048, rsassapkcs1.SHA256, rsassapkcs1.VariantNoPrefix, err)
	}
	// Valid modules are [2^2047, 2^2048).
	minModulus := new(big.Int).Exp(big.NewInt(2), big.NewInt(2047), nil)
	maxModulus := new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(2048), nil), big.NewInt(1))
	// The bytes size of the slice is correct, but the value is too small or too big.
	tooSmallModulus := make([]byte, 256)
	tooSmallModulusInt := new(big.Int).Sub(minModulus, big.NewInt(1))
	tooSmallModulusInt.FillBytes(tooSmallModulus)
	for _, tc := range []struct {
		name          string
		modulus       []byte
		idRequirement uint32
		parameters    *rsassapkcs1.Parameters
	}{
		{
			name:          "empty params",
			modulus:       modulus2048,
			idRequirement: 123,
			parameters:    &rsassapkcs1.Parameters{},
		},
		{
			name:          "nil modulus",
			modulus:       nil,
			idRequirement: 123,
			parameters:    tinkParams,
		},
		{
			name:          "modulus slice too small",
			modulus:       tooSmallModulus[:255],
			idRequirement: 123,
			parameters:    tinkParams,
		},
		{
			name:          "modulus value too small",
			modulus:       tooSmallModulus,
			idRequirement: 123,
			parameters:    tinkParams,
		},
		{
			name:          "modulus too big",
			modulus:       new(big.Int).Add(maxModulus, big.NewInt(1)).Bytes(),
			idRequirement: 123,
			parameters:    tinkParams,
		},
		{
			name:          "invalid ID requirement",
			modulus:       modulus2048,
			idRequirement: 123,
			parameters:    noPrefixParams,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := rsassapkcs1.NewPublicKey(tc.modulus, tc.idRequirement, tc.parameters); err == nil {
				t.Errorf("rsassapkcs1.NewPublicKey(%v, %d, %v) = nil, want error", tc.modulus, tc.idRequirement, tc.parameters)
			}
		})
	}
}

type testCase struct {
	name            string
	modulusSizeBits int
	hashType        rsassapkcs1.HashType
	publicExponent  int
	variant         rsassapkcs1.Variant
	modulus         []byte
	idRequirement   uint32
}

func testCases(t *testing.T) []testCase {
	t.Helper()
	testCases := []testCase{}
	for _, hashType := range []rsassapkcs1.HashType{rsassapkcs1.SHA256, rsassapkcs1.SHA384, rsassapkcs1.SHA512} {
		for _, variant := range []rsassapkcs1.Variant{rsassapkcs1.VariantTink, rsassapkcs1.VariantCrunchy, rsassapkcs1.VariantLegacy, rsassapkcs1.VariantNoPrefix} {
			for _, modulusSizeBits := range []int{2048, 3072, 4096} {
				idRequirement := 123
				if variant == rsassapkcs1.VariantNoPrefix {
					idRequirement = 0
				}
				var modulus []byte
				switch modulusSizeBits {
				case 2048:
					modulus = base64Decode(t, n2048Base64)
				case 3072:
					modulus = base64Decode(t, n3072Base64)
				case 4096:
					modulus = base64Decode(t, n4096Base64)
				default:
					t.Fatalf("invalid modulus size: %v", modulusSizeBits)
				}
				testCases = append(testCases, testCase{
					name:            fmt.Sprintf("%v-SHA%v-%v-minModule", modulusSizeBits, hashType, variant),
					modulusSizeBits: modulusSizeBits,
					hashType:        hashType,
					publicExponent:  f4,
					variant:         variant,
					modulus:         modulus,
					idRequirement:   uint32(idRequirement),
				})
			}
		}
	}

	return testCases
}

func TestNewPublicKey(t *testing.T) {
	for _, tc := range testCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			params, err := rsassapkcs1.NewParameters(tc.modulusSizeBits, tc.hashType, tc.publicExponent, tc.variant)
			if err != nil {
				t.Fatalf("rsassapkcs1.NewParameters(%v, %v, %v, %v) = %v, want nil", tc.modulusSizeBits, tc.hashType, tc.publicExponent, tc.variant, err)
			}
			key, err := rsassapkcs1.NewPublicKey(tc.modulus, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("rsassapkcs1.NewPublicKey(%v, %d, %v) = %v, want nil", tc.modulus, tc.idRequirement, params, err)
			}
			if got, want := key.Parameters(), params; !got.Equals(want) {
				t.Errorf("key.Parameters() = %v, want %v", got, want)
			}
			idRequirement, required := key.IDRequirement()
			if idRequirement != tc.idRequirement {
				t.Errorf("key.IDRequirement() = %v, want %v", idRequirement, tc.idRequirement)
			}
			if required != key.Parameters().HasIDRequirement() {
				t.Errorf("key.IDRequirement() = %v, want %v", required, key.Parameters().HasIDRequirement())
			}
			if got, want := idRequirement, tc.idRequirement; got != want {
				t.Errorf("key.IDRequirement() = %v, want %v", got, want)
			}
			if got, want := key.Modulus(), tc.modulus; !bytes.Equal(got, want) {
				t.Errorf("key.Modulus() = %v, want %v", got, want)
			}
			otherKey, err := rsassapkcs1.NewPublicKey(tc.modulus, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("rsassapkcs1.NewPublicKey(%v, %d, %v) = %v, want nil", tc.modulus, tc.idRequirement, params, err)
			}
			if !key.Equals(otherKey) {
				t.Errorf("key.Equals(otherKey) = false, want true")
			}
		})
	}
}

func TestNewPublicKeyMinMaxValues(t *testing.T) {
	// Valid values: [2^(n-1), 2^n).
	minModulus2048 := new(big.Int).Exp(big.NewInt(2), big.NewInt(2047), nil)
	maxModulus2048 := new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(2048), nil), big.NewInt(1))
	minModulus3072 := new(big.Int).Exp(big.NewInt(2), big.NewInt(3071), nil)
	maxModulus3072 := new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(3072), nil), big.NewInt(1))
	minModulus4096 := new(big.Int).Exp(big.NewInt(2), big.NewInt(4095), nil)
	maxModulus4096 := new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(4096), nil), big.NewInt(1))
	for _, tc := range []struct {
		name   string
		module []byte
		params *rsassapkcs1.Parameters
	}{
		{
			name:   "min module 2048 bit",
			module: minModulus2048.Bytes(),
			params: newParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantTink),
		},
		{
			name:   "max module 2048 bit",
			module: maxModulus2048.Bytes(),
			params: newParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantTink),
		},
		{
			name:   "min module 3072 bit",
			module: minModulus3072.Bytes(),
			params: newParameters(t, 3072, rsassapkcs1.SHA384, f4, rsassapkcs1.VariantTink),
		},
		{
			name:   "max module 3072 bit",
			module: maxModulus3072.Bytes(),
			params: newParameters(t, 3072, rsassapkcs1.SHA384, f4, rsassapkcs1.VariantTink),
		},
		{
			name:   "min module 4096 bit",
			module: minModulus4096.Bytes(),
			params: newParameters(t, 4096, rsassapkcs1.SHA512, f4, rsassapkcs1.VariantTink),
		},
		{
			name:   "max module 4096 bit",
			module: maxModulus4096.Bytes(),
			params: newParameters(t, 4096, rsassapkcs1.SHA512, f4, rsassapkcs1.VariantTink),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := rsassapkcs1.NewPublicKey(tc.module, 123, tc.params); err != nil {
				t.Errorf("rsassapkcs1.NewPublicKey(%v, %d, %v) err = %v, want nil", tc.module, 123, tc.params, err)
			}
		})
	}
}

func newParameters(t *testing.T, modulusSizeBits int, hashType rsassapkcs1.HashType, publicExponent int, variant rsassapkcs1.Variant) *rsassapkcs1.Parameters {
	t.Helper()
	params, err := rsassapkcs1.NewParameters(modulusSizeBits, hashType, publicExponent, variant)
	if err != nil {
		t.Fatalf("rsassapkcs1.NewParameters(%v, %v, %v, %v) = %v, want nil", modulusSizeBits, hashType, publicExponent, variant, err)
	}
	return params
}

func newPublicKey(t *testing.T, modulus []byte, idRequirement uint32, parameters *rsassapkcs1.Parameters) *rsassapkcs1.PublicKey {
	t.Helper()
	key, err := rsassapkcs1.NewPublicKey(modulus, idRequirement, parameters)
	if err != nil {
		t.Fatalf("rsassapkcs1.NewPublicKey(%v, %d, %v) = %v, want nil", modulus, idRequirement, parameters, err)
	}
	return key
}

func TestNewPublicKeyEqualsFailsIfDifferentKeys(t *testing.T) {
	validModulus2048 := base64Decode(t, n2048Base64)
	// From:
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/rsa_pkcs1_2048_test.json#L353
	otherN2048Base64 := "3ZBFkDl4CMQxQyliPZATRThDJRsTuLPE_vVFmBEq8-sxxxEDxiWZUWdOU72Tp-NtGUcuR06-gChobZUpSE2Lr-pKBLoZVVZnYWyEeGcFlACcm8aj7-UidMumTHJHR9ftwZTk_t3jKjKJ2Uwxk25-ehXXVvVISS9bNFuSfoxhi91VCsshoXrhSDBDg9ubPHuqPkyL2OhEqITao-GNVpmMsy-brk1B1WoY3dQxPICJt16du5EoRwusmwh_thkoqw-MTIk2CwIImQCNCOi9MfkHqAfoBWrWgA3_357Z2WSpOefkgRS4SXhVGsuFyd-RlvPv9VKG1s1LOagiqKd2Ohggjw"
	otherValidModulus2048 := base64Decode(t, otherN2048Base64)
	validModulus3072 := base64Decode(t, n3072Base64)
	for _, tc := range []struct {
		name string
		this *rsassapkcs1.PublicKey
		that *rsassapkcs1.PublicKey
	}{
		{
			name: "different modulus",
			this: newPublicKey(t, validModulus2048, 123, newParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantTink)),
			that: newPublicKey(t, otherValidModulus2048, 123, newParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantTink)),
		},
		{
			name: "different parameters",
			this: newPublicKey(t, validModulus2048, 123, newParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantTink)),
			that: newPublicKey(t, validModulus2048, 123, newParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantCrunchy)),
		},
		{
			name: "different ID requirement",
			this: newPublicKey(t, validModulus2048, 123, newParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantTink)),
			that: newPublicKey(t, validModulus2048, 234, newParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantTink)),
		},
		{
			name: "different modulus size",
			this: newPublicKey(t, validModulus2048, 123, newParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantTink)),
			that: newPublicKey(t, validModulus3072, 123, newParameters(t, 3072, rsassapkcs1.SHA384, f4, rsassapkcs1.VariantTink)),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.this.Equals(tc.that) {
				t.Errorf("tc.this.Equals(tc.that) = true, want false")
			}
			if tc.that.Equals(tc.this) {
				t.Errorf("tc.that.Equals(tc.this) = true, want false")
			}
		})
	}
}

func TestPublicKeyOutputPrefix(t *testing.T) {
	validModulus2048 := base64Decode(t, n2048Base64)
	for _, tc := range []struct {
		name          string
		variant       rsassapkcs1.Variant
		idRequirement uint32
		want          []byte
	}{
		{
			name:          "Tink",
			variant:       rsassapkcs1.VariantTink,
			idRequirement: uint32(0x01020304),
			want:          []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:          "Crunchy",
			variant:       rsassapkcs1.VariantCrunchy,
			idRequirement: uint32(0x01020304),
			want:          []byte{cryptofmt.LegacyStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:          "Legacy",
			variant:       rsassapkcs1.VariantLegacy,
			idRequirement: uint32(0x01020304),
			want:          []byte{cryptofmt.LegacyStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:          "NoPrefix",
			variant:       rsassapkcs1.VariantNoPrefix,
			idRequirement: 0,
			want:          nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := rsassapkcs1.NewParameters(2048, rsassapkcs1.SHA256, f4, tc.variant)
			if err != nil {
				t.Fatalf("rsassapkcs1.NewParameters(%v, %v, %v) = %v, want nil", 2048, rsassapkcs1.SHA256, tc.variant, err)
			}
			pubKey, err := rsassapkcs1.NewPublicKey(validModulus2048, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("rsassapkcs1.NewPublicKey(%v, %v, %v) err = %v, want nil", validModulus2048, tc.idRequirement, params, err)
			}
			if got, want := pubKey.OutputPrefix(), tc.want; !bytes.Equal(got, want) {
				t.Errorf("pubKey.OutputPrefix() = %v, want %v", got, want)
			}
		})
	}
}
