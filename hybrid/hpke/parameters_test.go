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

package hpke_test

import (
	"fmt"
	"testing"

	"github.com/tink-crypto/tink-go/v2/hybrid/hpke"
)

func TestNewParametersInvalidValues(t *testing.T) {
	testCases := []struct {
		name string
		opts hpke.ParametersOpts
	}{
		{
			name: "unknown kem id",
			opts: hpke.ParametersOpts{
				KEMID:   hpke.UnknownKEMID,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			},
		},
		{
			name: "unknown kdf id",
			opts: hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.UnknownKDFID,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			},
		},
		{
			name: "unknown aead id",
			opts: hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.UnknownAEADID,
				Variant: hpke.VariantTink,
			},
		},
		{
			name: "unknown variant",
			opts: hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantUnknown,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := hpke.NewParameters(tc.opts); err == nil {
				t.Errorf("hpke.NewParameters(%v) = nil, want error", tc.opts)
			}
		})
	}
}

type testCase struct {
	name string
	opts hpke.ParametersOpts
}

func testCases(t *testing.T) []testCase {
	testCases := []testCase{}
	for _, kemID := range []hpke.KEMID{hpke.DHKEM_P256_HKDF_SHA256, hpke.DHKEM_P384_HKDF_SHA384, hpke.DHKEM_P521_HKDF_SHA512, hpke.DHKEM_X25519_HKDF_SHA256} {
		for _, kdfID := range []hpke.KDFID{hpke.HKDFSHA256, hpke.HKDFSHA384, hpke.HKDFSHA512} {
			for _, aeadID := range []hpke.AEADID{hpke.AES256GCM, hpke.AES128GCM, hpke.ChaCha20Poly1305} {
				for _, variant := range []hpke.Variant{hpke.VariantTink, hpke.VariantCrunchy, hpke.VariantNoPrefix} {
					testCases = append(testCases, testCase{
						name: fmt.Sprintf("%v-%v-%v-%v", kemID, kdfID, aeadID, variant),
						opts: hpke.ParametersOpts{
							KEMID:   kemID,
							KDFID:   kdfID,
							AEADID:  aeadID,
							Variant: variant,
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
			params, err := hpke.NewParameters(tc.opts)
			if err != nil {
				t.Fatalf("hpke.NewParameters(%v) = %v, want nil", tc.opts, err)
			}
			if got, want := params.KEMID(), tc.opts.KEMID; got != want {
				t.Errorf("params.KEMID() = %v, want %v", got, want)
			}
			if got, want := params.KDFID(), tc.opts.KDFID; got != want {
				t.Errorf("params.KDFID() = %v, want %v", got, want)
			}
			if got, want := params.AEADID(), tc.opts.AEADID; got != want {
				t.Errorf("params.AEADID() = %v, want %v", got, want)
			}
			if got, want := params.Variant(), tc.opts.Variant; got != want {
				t.Errorf("params.Variant() = %v, want %v", got, want)
			}
			if got, want := params.HasIDRequirement(), tc.opts.Variant != hpke.VariantNoPrefix; got != want {
				t.Errorf("params.HasIDRequirement() = %v, want %v", got, want)
			}

			other, err := hpke.NewParameters(tc.opts)
			if err != nil {
				t.Fatalf("hpke.NewParameters() = %v, want nil", err)
			}
			if !params.Equal(other) {
				t.Errorf("params.Equal(other) = false, want true")
			}
		})
	}
}

func TestNewParametersNotEqual(t *testing.T) {
	testCases := []struct {
		name  string
		opts1 hpke.ParametersOpts
		opts2 hpke.ParametersOpts
	}{
		{
			name: "different kem id",
			opts1: hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			},
			opts2: hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P384_HKDF_SHA384,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			},
		},
		{
			name: "different kdf id",
			opts1: hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			},
			opts2: hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA384,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			},
		},
		{
			name: "different aead id",
			opts1: hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			},
			opts2: hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES128GCM,
				Variant: hpke.VariantTink,
			},
		},
		{
			name: "different variant",
			opts1: hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			},
			opts2: hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantNoPrefix,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params, err := hpke.NewParameters(tc.opts1)
			if err != nil {
				t.Fatalf("hpke.NewParameters(%v) = %v, want nil", tc.opts1, err)
			}
			other, err := hpke.NewParameters(tc.opts2)
			if err != nil {
				t.Fatalf("hpke.NewParameters(%v) = %v, want nil", tc.opts2, err)
			}
			if params.Equal(other) {
				t.Errorf("params.Equal(other) = true, want false")
			}
		})
	}
}

func TestKEMIDString(t *testing.T) {
	testCases := []struct {
		name  string
		kemID hpke.KEMID
		want  string
	}{
		{
			name:  "DHKEM_P256_HKDF_SHA256",
			kemID: hpke.DHKEM_P256_HKDF_SHA256,
			want:  "DHKEM-P256-HKDF-SHA256",
		},
		{
			name:  "DHKEM_P384_HKDF_SHA384",
			kemID: hpke.DHKEM_P384_HKDF_SHA384,
			want:  "DHKEM-P384-HKDF-SHA384",
		},
		{
			name:  "DHKEM_P521_HKDF_SHA512",
			kemID: hpke.DHKEM_P521_HKDF_SHA512,
			want:  "DHKEM-P521-HKDF-SHA512",
		},
		{
			name:  "DHKEM_X25519_HKDF_SHA256",
			kemID: hpke.DHKEM_X25519_HKDF_SHA256,
			want:  "DHKEM-X25519-HKDF-SHA256",
		},
		{
			name:  "UnknownKEMID",
			kemID: hpke.UnknownKEMID,
			want:  "UNKNOWN",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.kemID.String(); got != tc.want {
				t.Errorf("tc.kemID.String() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestKDFIDString(t *testing.T) {
	testCases := []struct {
		name  string
		kdfID hpke.KDFID
		want  string
	}{
		{
			name:  "HKDFSHA256",
			kdfID: hpke.HKDFSHA256,
			want:  "HKDF-SHA256",
		},
		{
			name:  "HKDFSHA384",
			kdfID: hpke.HKDFSHA384,
			want:  "HKDF-SHA384",
		},
		{
			name:  "HKDFSHA512",
			kdfID: hpke.HKDFSHA512,
			want:  "HKDF-SHA512",
		},
		{
			name:  "UnknownKDFID",
			kdfID: hpke.UnknownKDFID,
			want:  "UNKNOWN",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.kdfID.String(); got != tc.want {
				t.Errorf("tc.kdfID.String() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAEADIDString(t *testing.T) {
	testCases := []struct {
		name   string
		aeadID hpke.AEADID
		want   string
	}{
		{
			name:   "AES128GCM",
			aeadID: hpke.AES128GCM,
			want:   "AES-128-GCM",
		},
		{
			name:   "AES256GCM",
			aeadID: hpke.AES256GCM,
			want:   "AES-256-GCM",
		},
		{
			name:   "ChaCha20Poly1305",
			aeadID: hpke.ChaCha20Poly1305,
			want:   "ChaCha20-Poly1305",
		},
		{
			name:   "UnknownAEADID",
			aeadID: hpke.UnknownAEADID,
			want:   "UNKNOWN",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.aeadID.String(); got != tc.want {
				t.Errorf("tc.aeadID.String() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestVariantString(t *testing.T) {
	testCases := []struct {
		name    string
		variant hpke.Variant
		want    string
	}{
		{
			name:    "VariantTink",
			variant: hpke.VariantTink,
			want:    "TINK",
		},
		{
			name:    "VariantCrunchy",
			variant: hpke.VariantCrunchy,
			want:    "CRUNCHY",
		},
		{
			name:    "VariantNoPrefix",
			variant: hpke.VariantNoPrefix,
			want:    "NO_PREFIX",
		},
		{
			name:    "VariantUnknown",
			variant: hpke.VariantUnknown,
			want:    "UNKNOWN",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.variant.String(); got != tc.want {
				t.Errorf("tc.variant.String() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParametersOptsString(t *testing.T) {
	testCases := []struct {
		name string
		opts hpke.ParametersOpts
		want string
	}{
		{
			name: "valid parameters",
			opts: hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			},
			want: "KEMID: DHKEM-P256-HKDF-SHA256, KDFID: HKDF-SHA256, AEADID: AES-256-GCM, Variant: TINK",
		},
		{
			name: "unknown parameters",
			opts: hpke.ParametersOpts{
				KEMID:   hpke.UnknownKEMID,
				KDFID:   hpke.UnknownKDFID,
				AEADID:  hpke.UnknownAEADID,
				Variant: hpke.VariantUnknown,
			},
			want: "KEMID: UNKNOWN, KDFID: UNKNOWN, AEADID: UNKNOWN, Variant: UNKNOWN",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.opts.String(); got != tc.want {
				t.Errorf("tc.opts.String() = %q, want %q", got, tc.want)
			}
		})
	}
}
