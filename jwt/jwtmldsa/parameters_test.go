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

package jwtmldsa_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtmldsa"
)

func TestNewParameters(t *testing.T) {
	for _, tc := range []struct {
		kidStrategy jwtmldsa.KIDStrategy
		algorithm   jwtmldsa.Algorithm
	}{
		{jwtmldsa.Base64EncodedKeyIDAsKID, jwtmldsa.MLDSA44},
		{jwtmldsa.Base64EncodedKeyIDAsKID, jwtmldsa.MLDSA65},
		{jwtmldsa.Base64EncodedKeyIDAsKID, jwtmldsa.MLDSA87},
		{jwtmldsa.IgnoredKID, jwtmldsa.MLDSA44},
		{jwtmldsa.IgnoredKID, jwtmldsa.MLDSA65},
		{jwtmldsa.IgnoredKID, jwtmldsa.MLDSA87},
		{jwtmldsa.CustomKID, jwtmldsa.MLDSA44},
		{jwtmldsa.CustomKID, jwtmldsa.MLDSA65},
		{jwtmldsa.CustomKID, jwtmldsa.MLDSA87},
	} {
		t.Run(fmt.Sprintf("%v_%v", tc.kidStrategy, tc.algorithm), func(t *testing.T) {
			p, err := jwtmldsa.NewParameters(tc.kidStrategy, tc.algorithm)
			if err != nil {
				t.Fatalf("NewParameters(%v, %v) failed: %v", tc.kidStrategy, tc.algorithm, err)
			}
			if p.KIDStrategy() != tc.kidStrategy {
				t.Errorf("KIDStrategy() = %v, want %v", p.KIDStrategy(), tc.kidStrategy)
			}
			if p.Algorithm() != tc.algorithm {
				t.Errorf("Algorithm() = %v, want %v", p.Algorithm(), tc.algorithm)
			}
			if want := tc.kidStrategy == jwtmldsa.Base64EncodedKeyIDAsKID; p.HasIDRequirement() != want {
				t.Errorf("HasIDRequirement() = %v, want %v", p.HasIDRequirement(), want)
			}

			other, err := jwtmldsa.NewParameters(tc.kidStrategy, tc.algorithm)
			if err != nil {
				t.Fatalf("NewParameters(%v, %v) failed: %v", tc.kidStrategy, tc.algorithm, err)
			}
			if diff := cmp.Diff(p, other, cmp.AllowUnexported(jwtmldsa.Parameters{})); diff != "" {
				t.Errorf("NewParameters(%v, %v) returned unexpected diff (-want +got):\n%s", tc.kidStrategy, tc.algorithm, diff)
			}
		})
	}
}

func TestNewParameters_Errors(t *testing.T) {
	if _, err := jwtmldsa.NewParameters(jwtmldsa.UnknownKIDStrategy, jwtmldsa.MLDSA44); err == nil {
		t.Errorf("NewParameters(%v, %v) succeeded, want error", jwtmldsa.UnknownKIDStrategy, jwtmldsa.MLDSA44)
	}
	if _, err := jwtmldsa.NewParameters(jwtmldsa.Base64EncodedKeyIDAsKID, jwtmldsa.UnknownAlgorithm); err == nil {
		t.Errorf("NewParameters(%v, %v) succeeded, want error", jwtmldsa.Base64EncodedKeyIDAsKID, jwtmldsa.UnknownAlgorithm)
	}
}

func mustCreateParameters(t *testing.T, kidStrategy jwtmldsa.KIDStrategy, algorithm jwtmldsa.Algorithm) *jwtmldsa.Parameters {
	t.Helper()
	p, err := jwtmldsa.NewParameters(kidStrategy, algorithm)
	if err != nil {
		t.Fatalf("NewParameters(%v, %v) failed: %v", kidStrategy, algorithm, err)
	}
	return p
}

func TestEqual_Different(t *testing.T) {
	for _, tc := range []struct {
		name   string
		p1, p2 *jwtmldsa.Parameters
	}{
		{
			name: "DifferentKIDStrategy",
			p1:   mustCreateParameters(t, jwtmldsa.Base64EncodedKeyIDAsKID, jwtmldsa.MLDSA44),
			p2:   mustCreateParameters(t, jwtmldsa.IgnoredKID, jwtmldsa.MLDSA44),
		},
		{
			name: "DifferentAlgorithm",
			p1:   mustCreateParameters(t, jwtmldsa.Base64EncodedKeyIDAsKID, jwtmldsa.MLDSA44),
			p2:   mustCreateParameters(t, jwtmldsa.Base64EncodedKeyIDAsKID, jwtmldsa.MLDSA65),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.p1.Equal(tc.p2) {
				t.Errorf("(%v).Equal(%v) = true, want false", tc.p1, tc.p2)
			}
		})
	}
}
