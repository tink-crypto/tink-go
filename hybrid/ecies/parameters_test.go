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

package ecies_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead/aesctrhmac"
	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/aead/xchacha20poly1305"
	"github.com/tink-crypto/tink-go/v2/daead/aessiv"
	"github.com/tink-crypto/tink-go/v2/hybrid/ecies"
	"github.com/tink-crypto/tink-go/v2/key"
)

func mustCreateSupportedDEMPArams(t *testing.T) map[string]key.Parameters {
	aes128GCMParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 16,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("failed to create AES128-GCM parameters: %v", err)
	}
	aes256GCMParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("failed to create AES256-GCM parameters: %v", err)
	}
	aes256SIVParams, err := aessiv.NewParameters(64, aessiv.VariantNoPrefix)
	if err != nil {
		t.Fatalf("failed to create AES-SIV parameters: %v", err)
	}
	xchacha20poly1305Params, err := xchacha20poly1305.NewParameters(xchacha20poly1305.VariantNoPrefix)
	if err != nil {
		t.Fatalf("failed to create XChaCha20Poly1305 parameters: %v", err)
	}
	aes128CTRHMACSHA256Params, err := aesctrhmac.NewParameters(aesctrhmac.ParametersOpts{
		AESKeySizeInBytes:  16,
		HMACKeySizeInBytes: 32,
		IVSizeInBytes:      16,
		HashType:           aesctrhmac.SHA256,
		TagSizeInBytes:     16,
		Variant:            aesctrhmac.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("failed to create AES-CTR-HMAC parameters: %v", err)
	}
	aes256CTRHMACSHA256Params, err := aesctrhmac.NewParameters(aesctrhmac.ParametersOpts{
		AESKeySizeInBytes:  32,
		HMACKeySizeInBytes: 32,
		IVSizeInBytes:      16,
		HashType:           aesctrhmac.SHA256,
		TagSizeInBytes:     32,
		Variant:            aesctrhmac.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("failed to create AES256-CTR-HMAC parameters: %v", err)
	}
	return map[string]key.Parameters{
		"AES128-GCM-NoPrefix":             aes128GCMParams,
		"AES256-GCM-NoPrefix":             aes256GCMParams,
		"AES256-SIV-NoPrefix":             aes256SIVParams,
		"XChaCha20Poly1305-NoPrefix":      xchacha20poly1305Params,
		"AES128-CTR-HMAC-SHA256-NoPrefix": aes128CTRHMACSHA256Params,
		"AES256-CTR-HMAC-SHA256-NoPrefix": aes256CTRHMACSHA256Params,
	}
}

func TestNewParametersInvalidValues(t *testing.T) {
	demParams := mustCreateSupportedDEMPArams(t)

	// Unsupported DEM parameters.
	unsupportedDEMParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 24,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("failed to create unsupported DEM parameters: %v", err)
	}

	testCases := []struct {
		name string
		opts ecies.ParametersOpts
	}{
		{
			name: "unknown curve type",
			opts: ecies.ParametersOpts{
				CurveType:            ecies.UnknownCurveType,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.CompressedPointFormat,
				DEMParameters:        demParams["AES128-GCM-NoPrefix"],
				Variant:              ecies.VariantTink,
			},
		},
		{
			name: "unusupported DEM",
			opts: ecies.ParametersOpts{
				CurveType:            ecies.NISTP256,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.CompressedPointFormat,
				DEMParameters:        unsupportedDEMParams,
				Variant:              ecies.VariantTink,
			},
		},
		{
			name: "unspecified point format with NIST curve",
			opts: ecies.ParametersOpts{
				CurveType:            ecies.NISTP256,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.UnspecifiedPointFormat,
				DEMParameters:        demParams["AES128-GCM-NoPrefix"],
				Variant:              ecies.VariantTink,
			},
		},
		{
			name: "specified point format with X25519 curve",
			opts: ecies.ParametersOpts{
				CurveType:            ecies.X25519,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.CompressedPointFormat,
				DEMParameters:        demParams["AES128-GCM-NoPrefix"],
				Variant:              ecies.VariantTink,
			},
		},
		{
			name: "unknown variant",
			opts: ecies.ParametersOpts{
				CurveType:            ecies.X25519,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.UnspecifiedPointFormat,
				DEMParameters:        demParams["AES128-GCM-NoPrefix"],
				Variant:              ecies.VariantUnknown,
			},
		},
		{
			name: "unknown hash type",
			opts: ecies.ParametersOpts{
				CurveType:            ecies.NISTP256,
				HashType:             ecies.UnknownHashType,
				NISTCurvePointFormat: ecies.CompressedPointFormat,
				DEMParameters:        demParams["AES128-GCM-NoPrefix"],
				Variant:              ecies.VariantTink,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ecies.NewParameters(tc.opts); err == nil {
				t.Errorf("ecies.NewParameters(%v) = nil, want error", tc.opts)
			}
		})
	}
}

type testCase struct {
	name string
	opts ecies.ParametersOpts
}

func testCases(t *testing.T) []testCase {
	demParams := mustCreateSupportedDEMPArams(t)
	var testCases []testCase
	for _, hashType := range []ecies.HashType{ecies.SHA256, ecies.SHA384, ecies.SHA512} {
		for _, demID := range []string{"AES128-GCM-NoPrefix", "AES256-GCM-NoPrefix", "AES256-SIV-NoPrefix", "XChaCha20Poly1305-NoPrefix", "AES128-CTR-HMAC-SHA256-NoPrefix", "AES256-CTR-HMAC-SHA256-NoPrefix"} {
			for _, variant := range []ecies.Variant{ecies.VariantTink, ecies.VariantNoPrefix, ecies.VariantCrunchy} {
				for _, salt := range [][]byte{nil, []byte("salt")} {
					for _, curveType := range []ecies.CurveType{ecies.NISTP256, ecies.NISTP384, ecies.NISTP521} {
						for _, pointFormat := range []ecies.PointFormat{ecies.CompressedPointFormat, ecies.UncompressedPointFormat} {
							testCases = append(testCases, testCase{
								name: fmt.Sprintf("%v-%v-%v-%v-%v-%v", curveType, hashType, pointFormat, demID, variant, salt),
								opts: ecies.ParametersOpts{
									CurveType:            curveType,
									HashType:             hashType,
									NISTCurvePointFormat: pointFormat,
									DEMParameters:        demParams[demID],
									Salt:                 salt,
									Variant:              variant,
								},
							})
						}
					}
					testCases = append(testCases, testCase{
						name: fmt.Sprintf("%v-%v-%v-%v-%v-%v", ecies.X25519, hashType, ecies.UnspecifiedPointFormat, demID, variant, salt),
						opts: ecies.ParametersOpts{
							CurveType:            ecies.X25519,
							HashType:             hashType,
							NISTCurvePointFormat: ecies.UnspecifiedPointFormat,
							DEMParameters:        demParams[demID],
							Salt:                 salt,
							Variant:              variant,
						},
					})
				}
			}
		}
	}
	return testCases
}

func TestNewParameters(t *testing.T) {
	for _, tc := range testCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			params, err := ecies.NewParameters(tc.opts)
			if err != nil {
				t.Fatalf("ecies.NewParameters(%v) = %v, want nil", tc.opts, err)
			}
			if got, want := params.CurveType(), tc.opts.CurveType; got != want {
				t.Errorf("params.CurveType() = %v, want %v", got, want)
			}
			if got, want := params.HashType(), tc.opts.HashType; got != want {
				t.Errorf("params.HashType() = %v, want %v", got, want)
			}
			if got, want := params.NISTCurvePointFormat(), tc.opts.NISTCurvePointFormat; got != want {
				t.Errorf("params.NISTCurvePointFormat() = %v, want %v", got, want)
			}
			if got, want := params.Variant(), tc.opts.Variant; got != want {
				t.Errorf("params.Variant() = %v, want %v", got, want)
			}
			if got, want := params.DEMParameters(), tc.opts.DEMParameters; !got.Equal(want) {
				t.Errorf("params.DEMParameters() = %v, want %v", got, want)
			}
			if got, want := params.Salt(), tc.opts.Salt; !bytes.Equal(got, want) {
				t.Errorf("params.Salt() = %v, want %v", got, want)
			}
			if got, want := params.HasIDRequirement(), tc.opts.Variant != ecies.VariantNoPrefix; got != want {
				t.Errorf("params.HasIDRequirement() = %v, want %v", got, want)
			}
			other, err := ecies.NewParameters(tc.opts)
			if err != nil {
				t.Fatalf("ecies.NewParameters() = %v, want nil", err)
			}
			if !params.Equal(other) {
				t.Errorf("params.Equal(other) = false, want true")
			}
		})
	}
}

func TestParametersNotEqual(t *testing.T) {
	aesGCMDEMParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() err = %v, want nil", err)
	}
	aesGCMSIVDEMParams, err := aessiv.NewParameters(64, aessiv.VariantNoPrefix)
	if err != nil {
		t.Fatalf("aessiv.NewParameters() err = %v, want nil", err)
	}

	type paramsTestCase struct {
		params *ecies.Parameters
	}

	for _, tc := range []struct {
		name        string
		paramsOpts1 ecies.ParametersOpts
		paramsOpts2 ecies.ParametersOpts
	}{
		{
			name: "Different DEM parameters",
			paramsOpts1: ecies.ParametersOpts{
				CurveType:            ecies.X25519,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.UnspecifiedPointFormat,
				DEMParameters:        aesGCMDEMParams,
				Variant:              ecies.VariantTink,
			},
			paramsOpts2: ecies.ParametersOpts{
				CurveType:            ecies.X25519,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.UnspecifiedPointFormat,
				DEMParameters:        aesGCMSIVDEMParams,
				Variant:              ecies.VariantTink,
			},
		},
		{
			name: "Different variant",
			paramsOpts1: ecies.ParametersOpts{
				CurveType:            ecies.X25519,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.UnspecifiedPointFormat,
				DEMParameters:        aesGCMDEMParams,
				Variant:              ecies.VariantTink,
			},
			paramsOpts2: ecies.ParametersOpts{
				CurveType:            ecies.X25519,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.UnspecifiedPointFormat,
				DEMParameters:        aesGCMDEMParams,
				Variant:              ecies.VariantCrunchy,
			},
		},
		{
			name: "Different point format",
			paramsOpts1: ecies.ParametersOpts{
				CurveType:            ecies.NISTP256,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.CompressedPointFormat,
				DEMParameters:        aesGCMDEMParams,
				Variant:              ecies.VariantTink,
			},
			paramsOpts2: ecies.ParametersOpts{
				CurveType:            ecies.NISTP256,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.UncompressedPointFormat,
				DEMParameters:        aesGCMDEMParams,
				Variant:              ecies.VariantTink,
			},
		},
		{
			name: "Different NIST curve",
			paramsOpts1: ecies.ParametersOpts{
				CurveType:            ecies.NISTP256,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.CompressedPointFormat,
				DEMParameters:        aesGCMDEMParams,
				Variant:              ecies.VariantTink,
			},
			paramsOpts2: ecies.ParametersOpts{
				CurveType:            ecies.NISTP384,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.CompressedPointFormat,
				DEMParameters:        aesGCMDEMParams,
				Variant:              ecies.VariantTink,
			},
		},
		{
			name: "Different hash",
			paramsOpts1: ecies.ParametersOpts{
				CurveType:            ecies.NISTP256,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.CompressedPointFormat,
				DEMParameters:        aesGCMDEMParams,
				Variant:              ecies.VariantTink,
			},
			paramsOpts2: ecies.ParametersOpts{
				CurveType:            ecies.NISTP256,
				HashType:             ecies.SHA512,
				NISTCurvePointFormat: ecies.CompressedPointFormat,
				DEMParameters:        aesGCMDEMParams,
				Variant:              ecies.VariantTink,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params1, err := ecies.NewParameters(tc.paramsOpts1)
			if err != nil {
				t.Fatalf("ecies.NewParameters(%v) err = %v, want nil", tc.paramsOpts1, err)
			}
			params2, err := ecies.NewParameters(tc.paramsOpts2)
			if err != nil {
				t.Fatalf("ecies.NewParameters(%v) err = %v, want nil", tc.paramsOpts2, err)
			}
			if params1.Equal(params2) {
				t.Errorf("params1.Equal(params2) = true, want false")
			}
		})
	}
}
