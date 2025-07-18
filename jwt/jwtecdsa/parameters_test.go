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

package jwtecdsa_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtecdsa"
)

func TestNewParameters(t *testing.T) {
	for _, tc := range []struct {
		kidStrategy jwtecdsa.KIDStrategy
		algorithm   jwtecdsa.Algorithm
	}{
		{jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES256},
		{jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES384},
		{jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES512},
		{jwtecdsa.IgnoredKID, jwtecdsa.ES256},
		{jwtecdsa.IgnoredKID, jwtecdsa.ES384},
		{jwtecdsa.IgnoredKID, jwtecdsa.ES512},
		{jwtecdsa.CustomKID, jwtecdsa.ES256},
		{jwtecdsa.CustomKID, jwtecdsa.ES384},
		{jwtecdsa.CustomKID, jwtecdsa.ES512},
	} {
		t.Run(fmt.Sprintf("%v_%v", tc.kidStrategy, tc.algorithm), func(t *testing.T) {
			p, err := jwtecdsa.NewParameters(tc.kidStrategy, tc.algorithm)
			if err != nil {
				t.Fatalf("NewParameters(%v, %v) failed: %v", tc.kidStrategy, tc.algorithm, err)
			}
			if p.KIDStrategy() != tc.kidStrategy {
				t.Errorf("KIDStrategy() = %v, want %v", p.KIDStrategy(), tc.kidStrategy)
			}
			if p.Algorithm() != tc.algorithm {
				t.Errorf("Algorithm() = %v, want %v", p.Algorithm(), tc.algorithm)
			}
			if want := tc.kidStrategy == jwtecdsa.Base64EncodedKeyIDAsKID; p.HasIDRequirement() != want {
				t.Errorf("HasIDRequirement() = %v, want %v", p.HasIDRequirement(), want)
			}

			other, err := jwtecdsa.NewParameters(tc.kidStrategy, tc.algorithm)
			if err != nil {
				t.Fatalf("NewParameters(%v, %v) failed: %v", tc.kidStrategy, tc.algorithm, err)
			}
			if diff := cmp.Diff(p, other, cmp.AllowUnexported(jwtecdsa.Parameters{})); diff != "" {
				t.Errorf("NewParameters(%v, %v) returned unexpected diff (-want +got):\n%s", tc.kidStrategy, tc.algorithm, diff)
			}
		})
	}
}

func TestNewParameters_Errors(t *testing.T) {
	if _, err := jwtecdsa.NewParameters(jwtecdsa.UnknownKIDStrategy, jwtecdsa.ES256); err == nil {
		t.Errorf("NewParameters(%v, %v) succeeded, want error", jwtecdsa.UnknownKIDStrategy, jwtecdsa.ES256)
	}
	if _, err := jwtecdsa.NewParameters(jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.UnknownAlgorithm); err == nil {
		t.Errorf("NewParameters(%v, %v) succeeded, want error", jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.UnknownAlgorithm)
	}
}

func mustCreateParameters(t *testing.T, kidStrategy jwtecdsa.KIDStrategy, algorithm jwtecdsa.Algorithm) *jwtecdsa.Parameters {
	t.Helper()
	p, err := jwtecdsa.NewParameters(kidStrategy, algorithm)
	if err != nil {
		t.Fatalf("NewParameters(%v, %v) failed: %v", kidStrategy, algorithm, err)
	}
	return p
}

func TestEqual_Different(t *testing.T) {
	for _, tc := range []struct {
		name   string
		p1, p2 *jwtecdsa.Parameters
	}{
		{
			name: "DifferentKIDStrategy",
			p1:   mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES256),
			p2:   mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES384),
		},
		{
			name: "DifferentAlgorithm",
			p1:   mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES256),
			p2:   mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES512),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.p1.Equal(tc.p2) {
				t.Errorf("(%v).Equal(%v) = true, want false", tc.p1, tc.p2)
			}
		})
	}
}
