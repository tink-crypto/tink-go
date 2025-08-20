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

package jwtrsassapkcs1_test

import (
	"math/bits"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtrsassapkcs1"
)

const f4 = 65537

func TestNewParameters(t *testing.T) {
	tests := []struct {
		name    string
		opts    jwtrsassapkcs1.ParametersOpts
		wantErr bool
	}{{
		name: "valid",
		opts: jwtrsassapkcs1.ParametersOpts{
			ModulusSizeInBits: 2048,
			PublicExponent:    f4,
			Algorithm:         jwtrsassapkcs1.RS256,
			KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
		},
	}, {
		name: "valid 3072",
		opts: jwtrsassapkcs1.ParametersOpts{
			ModulusSizeInBits: 3072,
			PublicExponent:    f4,
			Algorithm:         jwtrsassapkcs1.RS384,
			KidStrategy:       jwtrsassapkcs1.IgnoredKID,
		},
	}, {
		name: "valid 4096",
		opts: jwtrsassapkcs1.ParametersOpts{
			ModulusSizeInBits: 4096,
			PublicExponent:    f4,
			Algorithm:         jwtrsassapkcs1.RS512,
			KidStrategy:       jwtrsassapkcs1.CustomKID,
		},
	}, {
		name: "invalid modulus size",
		opts: jwtrsassapkcs1.ParametersOpts{
			ModulusSizeInBits: 2047,
			PublicExponent:    f4,
			Algorithm:         jwtrsassapkcs1.RS256,
			KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
		},
		wantErr: true,
	}, {
		name: "invalid public exponent too small",
		opts: jwtrsassapkcs1.ParametersOpts{
			ModulusSizeInBits: 2048,
			PublicExponent:    3,
			Algorithm:         jwtrsassapkcs1.RS256,
			KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
		},
		wantErr: true,
	}, {
		name: "invalid public exponent even",
		opts: jwtrsassapkcs1.ParametersOpts{
			ModulusSizeInBits: 2048,
			PublicExponent:    65538,
			Algorithm:         jwtrsassapkcs1.RS256,
			KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
		},
		wantErr: true,
	}, {
		name: "unknown algorithm",
		opts: jwtrsassapkcs1.ParametersOpts{
			ModulusSizeInBits: 2048,
			PublicExponent:    f4,
			Algorithm:         jwtrsassapkcs1.UnknownAlgorithm,
			KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
		},
		wantErr: true,
	}, {
		name: "unknown kid strategy",
		opts: jwtrsassapkcs1.ParametersOpts{
			ModulusSizeInBits: 2048,
			PublicExponent:    f4,
			Algorithm:         jwtrsassapkcs1.RS256,
			KidStrategy:       jwtrsassapkcs1.UnknownKIDStrategy,
		},
		wantErr: true,
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := jwtrsassapkcs1.NewParameters(tc.opts)
			if (err != nil) != tc.wantErr {
				t.Errorf("jwtrsassapkcs1.NewParameters(%v) error = %v, wantErr %v", tc.opts, err, tc.wantErr)
			}
		})
	}

	// On 32 bit platforms, the public exponent cannot be larger than 1<<31.
	if bits.UintSize == 64 {
		expVal := 1 << (bits.UintSize/2 - 1)
		t.Run("exponent too larrge", func(t *testing.T) {
			if _, err := jwtrsassapkcs1.NewParameters(jwtrsassapkcs1.ParametersOpts{
				ModulusSizeInBits: 2048,
				PublicExponent:    expVal,
				Algorithm:         jwtrsassapkcs1.RS256,
				KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
			}); err == nil {
				t.Errorf("jwtrsassapkcs1.NewParameters() error = nil, want error")
			}
		})
	}

}

func TestParametersGetters(t *testing.T) {
	opts := jwtrsassapkcs1.ParametersOpts{
		ModulusSizeInBits: 2048,
		PublicExponent:    f4,
		Algorithm:         jwtrsassapkcs1.RS256,
		KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
	}
	p, err := jwtrsassapkcs1.NewParameters(opts)
	if err != nil {
		t.Fatalf("jwtrsassapkcs1.NewParameters(%v) error = %v", opts, err)
	}
	if p.ModulusSizeInBits() != opts.ModulusSizeInBits {
		t.Errorf("p.ModulusSizeInBitsjwtrsassapkcs1.() = %v, want %v", p.ModulusSizeInBits(), opts.ModulusSizeInBits)
	}
	if p.PublicExponent() != opts.PublicExponent {
		t.Errorf("p.PublicExponent() = %v, want %v", p.PublicExponent(), opts.PublicExponent)
	}
	if p.Algorithm() != opts.Algorithm {
		t.Errorf("p.Algorithm() = %v, want %v", p.Algorithm(), opts.Algorithm)
	}
	if p.KIDStrategy() != opts.KidStrategy {
		t.Errorf("p.KIDStrategy() = %v, want %v", p.KIDStrategy(), opts.KidStrategy)
	}
}

func TestParametersHasIDRequirement(t *testing.T) {
	tests := []struct {
		name string
		kid  jwtrsassapkcs1.KIDStrategy
		want bool
	}{{
		name: "Base64EncodedKeyIDAsKID",
		kid:  jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
		want: true,
	}, {
		name: "IgnoredKID",
		kid:  jwtrsassapkcs1.IgnoredKID,
		want: false,
	}, {
		name: "CustomKID",
		kid:  jwtrsassapkcs1.CustomKID,
		want: false,
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := jwtrsassapkcs1.ParametersOpts{
				ModulusSizeInBits: 2048,
				PublicExponent:    f4,
				Algorithm:         jwtrsassapkcs1.RS256,
				KidStrategy:       tc.kid,
			}
			p, err := jwtrsassapkcs1.NewParameters(opts)
			if err != nil {
				t.Fatalf("jwtrsassapkcs1.NewParameters(%v) error = %v", opts, err)
			}
			if p.HasIDRequirement() != tc.want {
				t.Errorf("p.HasIDRequirement() = %vjwtrsassapkcs1., want %v", p.HasIDRequirement(), tc.want)
			}
		})
	}
}

func TestParametersEqual(t *testing.T) {
	paramsA, err := jwtrsassapkcs1.NewParameters(jwtrsassapkcs1.ParametersOpts{
		ModulusSizeInBits: 2048,
		PublicExponent:    f4,
		Algorithm:         jwtrsassapkcs1.RS256,
		KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
	})
	if err != nil {
		t.Fatalf("jwtrsassapkcs1.NewParameters() err = %v", err)
	}
	paramsB, err := jwtrsassapkcs1.NewParameters(jwtrsassapkcs1.ParametersOpts{
		ModulusSizeInBits: 2048,
		PublicExponent:    f4,
		Algorithm:         jwtrsassapkcs1.RS256,
		KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
	})
	if err != nil {
		t.Fatalf("jwtrsassapkcs1.NewParameters() err = %v", err)
	}
	if !paramsA.Equal(paramsB) {
		t.Errorf("paramsA.Equal(paramsB) = false, want true")
	}
	if !paramsB.Equal(paramsA) {
		t.Errorf("paramsB.Equal(paramsA) = false, want true")
	}
	if !paramsA.Equal(paramsA) {
		t.Errorf("paramsA.Equal(paramsA) = false, want true")
	}

	tests := []jwtrsassapkcs1.ParametersOpts{
		{
			ModulusSizeInBits: 3072,
			PublicExponent:    f4,
			Algorithm:         jwtrsassapkcs1.RS256,
			KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
		},
		{
			ModulusSizeInBits: 2048,
			PublicExponent:    65539,
			Algorithm:         jwtrsassapkcs1.RS256,
			KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
		},
		{
			ModulusSizeInBits: 2048,
			PublicExponent:    f4,
			Algorithm:         jwtrsassapkcs1.RS384,
			KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
		},
		{
			ModulusSizeInBits: 2048,
			PublicExponent:    f4,
			Algorithm:         jwtrsassapkcs1.RS256,
			KidStrategy:       jwtrsassapkcs1.IgnoredKID,
		},
	}

	for _, tc := range tests {
		other, err := jwtrsassapkcs1.NewParameters(tc)
		if err != nil {
			t.Fatalf("jwtrsassapkcs1.NewParameters(%v) err = %v", tc, err)
		}
		if paramsA.Equal(other) {
			t.Errorf("paramsA.Equal(%v) = true, want false", other)
		}
	}
}

func TestAlgorithmString(t *testing.T) {
	tests := []struct {
		alg  jwtrsassapkcs1.Algorithm
		want string
	}{{
		alg:  jwtrsassapkcs1.RS256,
		want: "RS256",
	}, {
		alg:  jwtrsassapkcs1.RS384,
		want: "RS384",
	}, {
		alg:  jwtrsassapkcs1.RS512,
		want: "RS512",
	}, {
		alg:  jwtrsassapkcs1.UnknownAlgorithm,
		want: "UnknownAlgorithm",
	}}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if diff := cmp.Diff(tc.alg.String(), tc.want); diff != "" {
				t.Errorf("Algorithm.String() diff (-want +got): %s", diff)
			}
		})
	}
}

func TestKIDStrategyString(t *testing.T) {
	tests := []struct {
		kid  jwtrsassapkcs1.KIDStrategy
		want string
	}{{
		kid:  jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
		want: "Base64EncodedKeyIDAsKID",
	}, {
		kid:  jwtrsassapkcs1.IgnoredKID,
		want: "IgnoredKID",
	}, {
		kid:  jwtrsassapkcs1.CustomKID,
		want: "CustomKID",
	}, {
		kid:  jwtrsassapkcs1.UnknownKIDStrategy,
		want: "UnknownKIDStrategy",
	}}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if diff := cmp.Diff(tc.kid.String(), tc.want); diff != "" {
				t.Errorf("KIDStrategy.String() diff (-want +got): %s", diff)
			}
		})
	}
}
