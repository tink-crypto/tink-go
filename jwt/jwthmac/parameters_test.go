// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/Lycense-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

package jwthmac_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/jwt/jwthmac"
)

func TestNewParameters(t *testing.T) {
	for _, tc := range []struct {
		kidStrategy    jwthmac.KIDStrategy
		algorithm      jwthmac.Algorithm
		keySizeInBytes int
	}{
		{jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS256, 32},
		{jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS384, 48},
		{jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS512, 64},
		{jwthmac.IgnoredKID, jwthmac.HS256, 32},
		{jwthmac.IgnoredKID, jwthmac.HS384, 48},
		{jwthmac.IgnoredKID, jwthmac.HS512, 64},
		{jwthmac.CustomKID, jwthmac.HS256, 32 + 1}, // Use a larger key size than the minimum.
		{jwthmac.CustomKID, jwthmac.HS384, 48 + 1},
		{jwthmac.CustomKID, jwthmac.HS512, 64 + 1},
	} {
		t.Run(fmt.Sprintf("%v_%v_%v", tc.kidStrategy, tc.algorithm, tc.keySizeInBytes), func(t *testing.T) {
			p, err := jwthmac.NewParameters(tc.keySizeInBytes, tc.kidStrategy, tc.algorithm)
			if err != nil {
				t.Fatalf("NewParameters(%v, %v) failed: %v", tc.kidStrategy, tc.algorithm, err)
			}
			if p.KIDStrategy() != tc.kidStrategy {
				t.Errorf("KIDStrategy() = %v, want %v", p.KIDStrategy(), tc.kidStrategy)
			}
			if p.Algorithm() != tc.algorithm {
				t.Errorf("Algorithm() = %v, want %v", p.Algorithm(), tc.algorithm)
			}
			if want := tc.kidStrategy == jwthmac.Base64EncodedKeyIDAsKID; p.HasIDRequirement() != want {
				t.Errorf("HasIDRequirement() = %v, want %v", p.HasIDRequirement(), want)
			}

			other, err := jwthmac.NewParameters(tc.keySizeInBytes, tc.kidStrategy, tc.algorithm)
			if err != nil {
				t.Fatalf("NewParameters(%v, %v) failed: %v", tc.kidStrategy, tc.algorithm, err)
			}
			if diff := cmp.Diff(p, other, cmp.AllowUnexported(jwthmac.Parameters{})); diff != "" {
				t.Errorf("NewParameters(%v, %v) returned unexpected diff (-want +got):\n%s", tc.kidStrategy, tc.algorithm, diff)
			}
		})
	}
}

func TestNewParameters_Errors(t *testing.T) {
	for _, tc := range []struct {
		name           string
		keySizeInBytes int
		kidStrategy    jwthmac.KIDStrategy
		algorithm      jwthmac.Algorithm
	}{
		{
			name:           "UnknownKIDStrategy",
			keySizeInBytes: 32,
			kidStrategy:    jwthmac.UnknownKIDStrategy,
			algorithm:      jwthmac.HS256,
		},
		{
			name:           "UnknownAlgorithm",
			keySizeInBytes: 32,
			kidStrategy:    jwthmac.Base64EncodedKeyIDAsKID,
			algorithm:      jwthmac.UnknownAlgorithm,
		},
		{
			name:           "HS256_KeySizeTooSmall",
			keySizeInBytes: 32 - 1,
			kidStrategy:    jwthmac.Base64EncodedKeyIDAsKID,
			algorithm:      jwthmac.HS256,
		},
		{
			name:           "HS384_KeySizeTooSmall",
			keySizeInBytes: 48 - 1,
			kidStrategy:    jwthmac.Base64EncodedKeyIDAsKID,
			algorithm:      jwthmac.HS384,
		},
		{
			name:           "HS512_KeySizeTooSmall",
			keySizeInBytes: 64 - 1,
			kidStrategy:    jwthmac.Base64EncodedKeyIDAsKID,
			algorithm:      jwthmac.HS512,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := jwthmac.NewParameters(tc.keySizeInBytes, tc.kidStrategy, tc.algorithm); err == nil {
				t.Errorf("NewParameters(%v, %v, %v) succeeded, want error", tc.keySizeInBytes, tc.kidStrategy, tc.algorithm)
			} else {
				t.Logf("NewParameters(%v, %v, %v) failed: %v", tc.keySizeInBytes, tc.kidStrategy, tc.algorithm, err)
			}
		})
	}
}

func mustCreateParameters(t *testing.T, keySizeInBytes int, kidStrategy jwthmac.KIDStrategy, algorithm jwthmac.Algorithm) *jwthmac.Parameters {
	t.Helper()
	p, err := jwthmac.NewParameters(keySizeInBytes, kidStrategy, algorithm)
	if err != nil {
		t.Fatalf("NewParameters(%v, %v, %v) failed: %v", keySizeInBytes, kidStrategy, algorithm, err)
	}
	return p
}

func TestEqual_Different(t *testing.T) {
	for _, tc := range []struct {
		name   string
		p1, p2 *jwthmac.Parameters
	}{
		{
			name: "DifferentKIDStrategy",
			p1:   mustCreateParameters(t, 32, jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS256),
			p2:   mustCreateParameters(t, 32, jwthmac.CustomKID, jwthmac.HS256),
		},
		{
			name: "DifferentAlgorithm",
			p1:   mustCreateParameters(t, 64, jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS256),
			p2:   mustCreateParameters(t, 64, jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS512),
		},
		{
			name: "DifferentKeySize",
			p1:   mustCreateParameters(t, 64, jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS512),
			p2:   mustCreateParameters(t, 65, jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS512),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.p1.Equal(tc.p2) {
				t.Errorf("(%v).Equal(%v) = true, want false", tc.p1, tc.p2)
			}
		})
	}
}
