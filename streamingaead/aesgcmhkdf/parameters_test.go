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

package aesgcmhkdf_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/streamingaead/aesgcmhkdf"
)

func TestNewParameters_InvalidKeySize(t *testing.T) {
	for _, derivedKeySize := range []int{16, 32} {
		opts := aesgcmhkdf.ParametersOpts{
			KeySizeInBytes:        derivedKeySize - 1,
			DerivedKeySizeInBytes: derivedKeySize,
			HKDFHashType:          aesgcmhkdf.SHA256,
			SegmentSizeInBytes:    4096,
		}
		if _, err := aesgcmhkdf.NewParameters(opts); err == nil {
			t.Errorf("aesgcmhkdf.NewParameters(%v) err = nil, want error", opts)
		}
	}
}

func TestNewParameters_InvalidDerivedKeySize(t *testing.T) {
	for _, derivedKeySize := range []int{1, 15, 17, 31, 33} {
		opts := aesgcmhkdf.ParametersOpts{
			KeySizeInBytes:        32,
			DerivedKeySizeInBytes: derivedKeySize,
			HKDFHashType:          aesgcmhkdf.SHA256,
			SegmentSizeInBytes:    4096,
		}
		if _, err := aesgcmhkdf.NewParameters(opts); err == nil {
			t.Errorf("aesgcmhkdf.NewParameters(%v) err = nil, want error", opts)
		}
	}
}

func TestNewParameters_InvalidHashType(t *testing.T) {
	opts := aesgcmhkdf.ParametersOpts{
		KeySizeInBytes:        16,
		DerivedKeySizeInBytes: 16,
		HKDFHashType:          aesgcmhkdf.HashTypeUnknown,
		SegmentSizeInBytes:    4096,
	}
	if _, err := aesgcmhkdf.NewParameters(opts); err == nil {
		t.Errorf("aesgcmhkdf.NewParameters(%v) err = nil, want error", opts)
	}

}

func TestNewParameters_InvalidSegmentSize(t *testing.T) {
	for _, derivedKeySize := range []int{16, 32} {
		opts := aesgcmhkdf.ParametersOpts{
			KeySizeInBytes:        derivedKeySize,
			DerivedKeySizeInBytes: derivedKeySize,
			HKDFHashType:          aesgcmhkdf.SHA256,
			SegmentSizeInBytes:    int32(derivedKeySize) + 24, // 1 byte short of the minimum.
		}
		if _, err := aesgcmhkdf.NewParameters(opts); err == nil {
			t.Errorf("aesgcmhkdf.NewParameters(%v) err = nil, want error", opts)
		}
	}
}

func TestNewParameters(t *testing.T) {
	for _, test := range []struct {
		name string
		opts aesgcmhkdf.ParametersOpts
	}{
		{
			name: "16-byte key, 16-byte derived key, SHA256",
			opts: aesgcmhkdf.ParametersOpts{
				KeySizeInBytes:        16,
				DerivedKeySizeInBytes: 16,
				HKDFHashType:          aesgcmhkdf.SHA256,
				SegmentSizeInBytes:    16 + 24 + 1, // Minimum segment size.
			},
		},
		{
			name: "32-byte key, 32-byte derived key, SHA512",
			opts: aesgcmhkdf.ParametersOpts{
				KeySizeInBytes:        32,
				DerivedKeySizeInBytes: 32,
				HKDFHashType:          aesgcmhkdf.SHA512,
				SegmentSizeInBytes:    1024,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			params, err := aesgcmhkdf.NewParameters(test.opts)
			if err != nil {
				t.Fatalf("aesgcmhkdf.NewParameters(%v) err = %v, want nil", test.opts, err)
			}
			if params.HasIDRequirement() {
				t.Errorf("params.HasIDRequirement() = true, want false")
			}
			if params.KeySizeInBytes() != test.opts.KeySizeInBytes {
				t.Errorf("params.KeySizeInBytes() = %v, want %v", params.KeySizeInBytes(), test.opts.KeySizeInBytes)
			}
			if params.DerivedKeySizeInBytes() != test.opts.DerivedKeySizeInBytes {
				t.Errorf("params.DerivedKeySizeInBytes() = %v, want %v", params.DerivedKeySizeInBytes(), test.opts.DerivedKeySizeInBytes)
			}
			if params.HKDFHashType() != test.opts.HKDFHashType {
				t.Errorf("params.HKDFHashType() = %v, want %v", params.HKDFHashType(), test.opts.HKDFHashType)
			}
			if params.SegmentSizeInBytes() != test.opts.SegmentSizeInBytes {
				t.Errorf("params.SegmentSizeInBytes() = %v, want %v", params.SegmentSizeInBytes(), test.opts.SegmentSizeInBytes)
			}
			otherParams, err := aesgcmhkdf.NewParameters(test.opts)
			if err != nil {
				t.Fatalf("aesgcmhkdf.NewParameters(%v) err = %v, want nil", test.opts, err)
			}
			if diff := cmp.Diff(params, otherParams); diff != "" {
				t.Errorf("params.Equal(otherParams) returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParametersEqual_FalseIfDifferent(t *testing.T) {
	for _, test := range []struct {
		name  string
		opts1 aesgcmhkdf.ParametersOpts
		opts2 aesgcmhkdf.ParametersOpts
	}{
		{
			name: "different key size",
			opts1: aesgcmhkdf.ParametersOpts{
				KeySizeInBytes:        16,
				DerivedKeySizeInBytes: 16,
				HKDFHashType:          aesgcmhkdf.SHA256,
				SegmentSizeInBytes:    4096,
			},
			opts2: aesgcmhkdf.ParametersOpts{
				KeySizeInBytes:        32,
				DerivedKeySizeInBytes: 16,
				HKDFHashType:          aesgcmhkdf.SHA256,
				SegmentSizeInBytes:    4096,
			},
		},
		{
			name: "different derived key size",
			opts1: aesgcmhkdf.ParametersOpts{
				KeySizeInBytes:        32,
				DerivedKeySizeInBytes: 16,
				HKDFHashType:          aesgcmhkdf.SHA256,
				SegmentSizeInBytes:    4096,
			},
			opts2: aesgcmhkdf.ParametersOpts{
				KeySizeInBytes:        32,
				DerivedKeySizeInBytes: 32,
				HKDFHashType:          aesgcmhkdf.SHA256,
				SegmentSizeInBytes:    4096,
			},
		},
		{
			name: "different hash type",
			opts1: aesgcmhkdf.ParametersOpts{
				KeySizeInBytes:        16,
				DerivedKeySizeInBytes: 16,
				HKDFHashType:          aesgcmhkdf.SHA256,
				SegmentSizeInBytes:    4096,
			},
			opts2: aesgcmhkdf.ParametersOpts{
				KeySizeInBytes:        16,
				DerivedKeySizeInBytes: 16,
				HKDFHashType:          aesgcmhkdf.SHA512,
				SegmentSizeInBytes:    4096,
			},
		},
		{
			name: "different ciphertext segment size",
			opts1: aesgcmhkdf.ParametersOpts{
				KeySizeInBytes:        16,
				DerivedKeySizeInBytes: 16,
				HKDFHashType:          aesgcmhkdf.SHA256,
				SegmentSizeInBytes:    4096,
			},
			opts2: aesgcmhkdf.ParametersOpts{
				KeySizeInBytes:        16,
				DerivedKeySizeInBytes: 16,
				HKDFHashType:          aesgcmhkdf.SHA256,
				SegmentSizeInBytes:    8192,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			params1, err := aesgcmhkdf.NewParameters(test.opts1)
			if err != nil {
				t.Fatalf("aesgcmhkdf.NewParameters(%v) err = %v, want nil", test.opts1, err)
			}
			params2, err := aesgcmhkdf.NewParameters(test.opts2)
			if err != nil {
				t.Fatalf("aesgcmhkdf.NewParameters(%v) err = %v, want nil", test.opts2, err)
			}
			if diff := cmp.Diff(params1, params2); diff == "" {
				t.Errorf("params1.Equal(params2) returned empty diff, want non-empty diff")
			}
		})
	}
}
