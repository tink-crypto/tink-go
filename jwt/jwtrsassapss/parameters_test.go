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

package jwtrsassapss_test

import (
	"math/bits"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtrsassapss"
)

const f4 = 65537

func TestNewParameters(t *testing.T) {
	tests := []struct {
		name    string
		opts    jwtrsassapss.ParametersOpts
		wantErr bool
	}{{
		name: "valid",
		opts: jwtrsassapss.ParametersOpts{
			ModulusSizeInBits: 2048,
			PublicExponent:    f4,
			Algorithm:         jwtrsassapss.PS256,
			KidStrategy:       jwtrsassapss.Base64EncodedKeyIDAsKID,
		},
	}, {
		name: "valid 3072",
		opts: jwtrsassapss.ParametersOpts{
			ModulusSizeInBits: 3072,
			PublicExponent:    f4,
			Algorithm:         jwtrsassapss.PS384,
			KidStrategy:       jwtrsassapss.IgnoredKID,
		},
	}, {
		name: "valid 4096",
		opts: jwtrsassapss.ParametersOpts{
			ModulusSizeInBits: 4096,
			PublicExponent:    f4,
			Algorithm:         jwtrsassapss.PS512,
			KidStrategy:       jwtrsassapss.CustomKID,
		},
	}, {
		name: "invalid modulus size",
		opts: jwtrsassapss.ParametersOpts{
			ModulusSizeInBits: 2047,
			PublicExponent:    f4,
			Algorithm:         jwtrsassapss.PS256,
			KidStrategy:       jwtrsassapss.Base64EncodedKeyIDAsKID,
		},
		wantErr: true,
	}, {
		name: "invalid public exponent too small",
		opts: jwtrsassapss.ParametersOpts{
			ModulusSizeInBits: 2048,
			PublicExponent:    3,
			Algorithm:         jwtrsassapss.PS256,
			KidStrategy:       jwtrsassapss.Base64EncodedKeyIDAsKID,
		},
		wantErr: true,
	}, {
		name: "invalid public exponent even",
		opts: jwtrsassapss.ParametersOpts{
			ModulusSizeInBits: 2048,
			PublicExponent:    65538,
			Algorithm:         jwtrsassapss.PS256,
			KidStrategy:       jwtrsassapss.Base64EncodedKeyIDAsKID,
		},
		wantErr: true,
	}, {
		name: "unknown algorithm",
		opts: jwtrsassapss.ParametersOpts{
			ModulusSizeInBits: 2048,
			PublicExponent:    f4,
			Algorithm:         jwtrsassapss.UnknownAlgorithm,
			KidStrategy:       jwtrsassapss.Base64EncodedKeyIDAsKID,
		},
		wantErr: true,
	}, {
		name: "unknown kid strategy",
		opts: jwtrsassapss.ParametersOpts{
			ModulusSizeInBits: 2048,
			PublicExponent:    f4,
			Algorithm:         jwtrsassapss.PS256,
			KidStrategy:       jwtrsassapss.UnknownKIDStrategy,
		},
		wantErr: true,
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := jwtrsassapss.NewParameters(tc.opts)
			if (err != nil) != tc.wantErr {
				t.Errorf("jwtrsassapss.NewParameters(%v) error = %v, wantErr %v", tc.opts, err, tc.wantErr)
			}
		})
	}

	// On 32 bit platforms, the public exponent cannot be larger than 1<<31.
	if bits.UintSize == 64 {
		expVal := 1 << (bits.UintSize/2 - 1)
		t.Run("exponent too larrge", func(t *testing.T) {
			if _, err := jwtrsassapss.NewParameters(jwtrsassapss.ParametersOpts{
				ModulusSizeInBits: 2048,
				PublicExponent:    expVal,
				Algorithm:         jwtrsassapss.PS256,
				KidStrategy:       jwtrsassapss.Base64EncodedKeyIDAsKID,
			}); err == nil {
				t.Errorf("jwtrsassapss.NewParameters() error = nil, want error")
			}
		})
	}

}

func TestParametersGetters(t *testing.T) {
	opts := jwtrsassapss.ParametersOpts{
		ModulusSizeInBits: 2048,
		PublicExponent:    f4,
		Algorithm:         jwtrsassapss.PS256,
		KidStrategy:       jwtrsassapss.Base64EncodedKeyIDAsKID,
	}
	p, err := jwtrsassapss.NewParameters(opts)
	if err != nil {
		t.Fatalf("jwtrsassapss.NewParameters(%v) error = %v", opts, err)
	}
	if p.ModulusSizeInBits() != opts.ModulusSizeInBits {
		t.Errorf("p.ModulusSizeInBitsjwtrsassapss.() = %v, want %v", p.ModulusSizeInBits(), opts.ModulusSizeInBits)
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
		kid  jwtrsassapss.KIDStrategy
		want bool
	}{{
		name: "Base64EncodedKeyIDAsKID",
		kid:  jwtrsassapss.Base64EncodedKeyIDAsKID,
		want: true,
	}, {
		name: "IgnoredKID",
		kid:  jwtrsassapss.IgnoredKID,
		want: false,
	}, {
		name: "CustomKID",
		kid:  jwtrsassapss.CustomKID,
		want: false,
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := jwtrsassapss.ParametersOpts{
				ModulusSizeInBits: 2048,
				PublicExponent:    f4,
				Algorithm:         jwtrsassapss.PS256,
				KidStrategy:       tc.kid,
			}
			p, err := jwtrsassapss.NewParameters(opts)
			if err != nil {
				t.Fatalf("jwtrsassapss.NewParameters(%v) error = %v", opts, err)
			}
			if p.HasIDRequirement() != tc.want {
				t.Errorf("p.HasIDRequirement() = %vjwtrsassapss., want %v", p.HasIDRequirement(), tc.want)
			}
		})
	}
}

func TestParametersEqual(t *testing.T) {
	paramsA, err := jwtrsassapss.NewParameters(jwtrsassapss.ParametersOpts{
		ModulusSizeInBits: 2048,
		PublicExponent:    f4,
		Algorithm:         jwtrsassapss.PS256,
		KidStrategy:       jwtrsassapss.Base64EncodedKeyIDAsKID,
	})
	if err != nil {
		t.Fatalf("jwtrsassapss.NewParameters() err = %v", err)
	}
	paramsB, err := jwtrsassapss.NewParameters(jwtrsassapss.ParametersOpts{
		ModulusSizeInBits: 2048,
		PublicExponent:    f4,
		Algorithm:         jwtrsassapss.PS256,
		KidStrategy:       jwtrsassapss.Base64EncodedKeyIDAsKID,
	})
	if err != nil {
		t.Fatalf("jwtrsassapss.NewParameters() err = %v", err)
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

	tests := []jwtrsassapss.ParametersOpts{
		{
			ModulusSizeInBits: 3072,
			PublicExponent:    f4,
			Algorithm:         jwtrsassapss.PS256,
			KidStrategy:       jwtrsassapss.Base64EncodedKeyIDAsKID,
		},
		{
			ModulusSizeInBits: 2048,
			PublicExponent:    65539,
			Algorithm:         jwtrsassapss.PS256,
			KidStrategy:       jwtrsassapss.Base64EncodedKeyIDAsKID,
		},
		{
			ModulusSizeInBits: 2048,
			PublicExponent:    f4,
			Algorithm:         jwtrsassapss.PS384,
			KidStrategy:       jwtrsassapss.Base64EncodedKeyIDAsKID,
		},
		{
			ModulusSizeInBits: 2048,
			PublicExponent:    f4,
			Algorithm:         jwtrsassapss.PS256,
			KidStrategy:       jwtrsassapss.IgnoredKID,
		},
	}

	for _, tc := range tests {
		other, err := jwtrsassapss.NewParameters(tc)
		if err != nil {
			t.Fatalf("jwtrsassapss.NewParameters(%v) err = %v", tc, err)
		}
		if paramsA.Equal(other) {
			t.Errorf("paramsA.Equal(%v) = true, want false", other)
		}
	}
}

func TestAlgorithmString(t *testing.T) {
	tests := []struct {
		alg  jwtrsassapss.Algorithm
		want string
	}{{
		alg:  jwtrsassapss.PS256,
		want: "PS256",
	}, {
		alg:  jwtrsassapss.PS384,
		want: "PS384",
	}, {
		alg:  jwtrsassapss.PS512,
		want: "PS512",
	}, {
		alg:  jwtrsassapss.UnknownAlgorithm,
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
		kid  jwtrsassapss.KIDStrategy
		want string
	}{{
		kid:  jwtrsassapss.Base64EncodedKeyIDAsKID,
		want: "Base64EncodedKeyIDAsKID",
	}, {
		kid:  jwtrsassapss.IgnoredKID,
		want: "IgnoredKID",
	}, {
		kid:  jwtrsassapss.CustomKID,
		want: "CustomKID",
	}, {
		kid:  jwtrsassapss.UnknownKIDStrategy,
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
