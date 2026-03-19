// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package compositemldsa_test

import (
	"fmt"
	"testing"

	"github.com/tink-crypto/tink-go/v2/signature/compositemldsa"
)

func isSupported(classicalAlgorithm compositemldsa.ClassicalAlgorithm, instance compositemldsa.MLDSAInstance) bool {
	switch instance {
	case compositemldsa.MLDSA65:
		switch classicalAlgorithm {
		case compositemldsa.Ed25519, compositemldsa.ECDSAP256, compositemldsa.ECDSAP384, compositemldsa.RSA3072PSS, compositemldsa.RSA4096PSS, compositemldsa.RSA3072PKCS1, compositemldsa.RSA4096PKCS1:
			return true
		default:
			return false
		}
	case compositemldsa.MLDSA87:
		switch classicalAlgorithm {
		case compositemldsa.ECDSAP384, compositemldsa.ECDSAP521, compositemldsa.RSA3072PSS, compositemldsa.RSA4096PSS:
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func TestNewParametersSupported(t *testing.T) {
	tests := []struct {
		classicalAlgorithm compositemldsa.ClassicalAlgorithm
		instance           compositemldsa.MLDSAInstance
		variant            compositemldsa.Variant
	}{
		// MLDSA65
		{compositemldsa.Ed25519, compositemldsa.MLDSA65, compositemldsa.VariantTink},
		{compositemldsa.Ed25519, compositemldsa.MLDSA65, compositemldsa.VariantNoPrefix},
		{compositemldsa.ECDSAP256, compositemldsa.MLDSA65, compositemldsa.VariantTink},
		{compositemldsa.ECDSAP256, compositemldsa.MLDSA65, compositemldsa.VariantNoPrefix},
		{compositemldsa.ECDSAP384, compositemldsa.MLDSA65, compositemldsa.VariantTink},
		{compositemldsa.ECDSAP384, compositemldsa.MLDSA65, compositemldsa.VariantNoPrefix},
		{compositemldsa.RSA3072PSS, compositemldsa.MLDSA65, compositemldsa.VariantTink},
		{compositemldsa.RSA3072PSS, compositemldsa.MLDSA65, compositemldsa.VariantNoPrefix},
		{compositemldsa.RSA4096PSS, compositemldsa.MLDSA65, compositemldsa.VariantTink},
		{compositemldsa.RSA4096PSS, compositemldsa.MLDSA65, compositemldsa.VariantNoPrefix},
		{compositemldsa.RSA3072PKCS1, compositemldsa.MLDSA65, compositemldsa.VariantTink},
		{compositemldsa.RSA3072PKCS1, compositemldsa.MLDSA65, compositemldsa.VariantNoPrefix},
		{compositemldsa.RSA4096PKCS1, compositemldsa.MLDSA65, compositemldsa.VariantTink},
		{compositemldsa.RSA4096PKCS1, compositemldsa.MLDSA65, compositemldsa.VariantNoPrefix},
		// MLDSA87
		{compositemldsa.ECDSAP384, compositemldsa.MLDSA87, compositemldsa.VariantTink},
		{compositemldsa.ECDSAP384, compositemldsa.MLDSA87, compositemldsa.VariantNoPrefix},
		{compositemldsa.ECDSAP521, compositemldsa.MLDSA87, compositemldsa.VariantTink},
		{compositemldsa.ECDSAP521, compositemldsa.MLDSA87, compositemldsa.VariantNoPrefix},
		{compositemldsa.RSA3072PSS, compositemldsa.MLDSA87, compositemldsa.VariantTink},
		{compositemldsa.RSA3072PSS, compositemldsa.MLDSA87, compositemldsa.VariantNoPrefix},
		{compositemldsa.RSA4096PSS, compositemldsa.MLDSA87, compositemldsa.VariantTink},
		{compositemldsa.RSA4096PSS, compositemldsa.MLDSA87, compositemldsa.VariantNoPrefix},
	}
	for _, tc := range tests {
		params, err := compositemldsa.NewParameters(tc.classicalAlgorithm, tc.instance, tc.variant)
		if err != nil {
			t.Errorf("compositemldsa.NewParameters(%v, %v, %v) err = %v, want nil", tc.classicalAlgorithm, tc.instance, tc.variant, err)
		}
		if got := params.ClassicalAlgorithm(); got != tc.classicalAlgorithm {
			t.Errorf("params.ClassicalAlgorithm() = %v, want %v", got, tc.classicalAlgorithm)
		}
		if got := params.MLDSAInstance(); got != tc.instance {
			t.Errorf("params.MlDsaInstance() = %v, want %v", got, tc.instance)
		}
		if got := params.Variant(); got != tc.variant {
			t.Errorf("params.Variant() = %v, want %v", got, tc.variant)
		}
	}
}

func TestNewParametersUnsupported(t *testing.T) {
	tests := []struct {
		classicalAlgorithm compositemldsa.ClassicalAlgorithm
		instance           compositemldsa.MLDSAInstance
		variant            compositemldsa.Variant
	}{
		// Unknown
		{compositemldsa.UnknownAlgorithm, compositemldsa.MLDSA65, compositemldsa.VariantTink},
		{compositemldsa.Ed25519, compositemldsa.UnknownInstance, compositemldsa.VariantTink},
		{compositemldsa.Ed25519, compositemldsa.MLDSA65, compositemldsa.VariantUnknown},
		// MLDSA65 unsupported
		{compositemldsa.ECDSAP521, compositemldsa.MLDSA65, compositemldsa.VariantTink},
		// MLDSA87 unsupported
		{compositemldsa.Ed25519, compositemldsa.MLDSA87, compositemldsa.VariantTink},
		{compositemldsa.ECDSAP256, compositemldsa.MLDSA87, compositemldsa.VariantTink},
		{compositemldsa.RSA3072PKCS1, compositemldsa.MLDSA87, compositemldsa.VariantTink},
		{compositemldsa.RSA4096PKCS1, compositemldsa.MLDSA87, compositemldsa.VariantTink},
	}
	for _, tc := range tests {
		_, err := compositemldsa.NewParameters(tc.classicalAlgorithm, tc.instance, tc.variant)
		if err == nil {
			t.Errorf("compositemldsa.NewParameters(%v, %v, %v) err = nil, want error", tc.classicalAlgorithm, tc.instance, tc.variant)
		}
	}
}

func TestParametersEqual(t *testing.T) {
	for _, classicalAlgorithm := range []compositemldsa.ClassicalAlgorithm{
		compositemldsa.RSA3072PSS,
		compositemldsa.ECDSAP384,
	} {
		for _, instance := range []compositemldsa.MLDSAInstance{
			compositemldsa.MLDSA65,
			compositemldsa.MLDSA87,
		} {
			t.Run(fmt.Sprintf("%v/%v", classicalAlgorithm, instance), func(t *testing.T) {
				tinkParams, err := compositemldsa.NewParameters(classicalAlgorithm, instance, compositemldsa.VariantTink)
				if err != nil {
					t.Fatalf("NewParameters(classicalAlgorithm, instance, compositemldsa.VariantTink) err = %v", err)
				}
				noPrefixParams, err := compositemldsa.NewParameters(classicalAlgorithm, instance, compositemldsa.VariantNoPrefix)
				if err != nil {
					t.Fatalf("NewParameters(classicalAlgorithm, instance, compositemldsa.VariantNoPrefix) err = %v", err)
				}
				if !tinkParams.Equal(tinkParams) {
					t.Errorf("tinkParams.Equal(tinkParams) = false, want true")
				}
				if !noPrefixParams.Equal(noPrefixParams) {
					t.Errorf("noPrefixParams.Equal(noPrefixParams) = false, want true")
				}
				if tinkParams.Equal(noPrefixParams) {
					t.Errorf("tinkParams.Equal(noPrefixParams) = true, want false")
				}
			})
		}
	}
	// Test inequality for different classical algorithms and instances.
	p1, err := compositemldsa.NewParameters(compositemldsa.Ed25519, compositemldsa.MLDSA65, compositemldsa.VariantTink)
	if err != nil {
		t.Fatalf("%v", err)
	}
	p2, err := compositemldsa.NewParameters(compositemldsa.ECDSAP384, compositemldsa.MLDSA65, compositemldsa.VariantTink)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if p1.Equal(p2) {
		t.Errorf("p1.Equal(p2) = true, want false")
	}
	p3, err := compositemldsa.NewParameters(compositemldsa.ECDSAP384, compositemldsa.MLDSA87, compositemldsa.VariantTink)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if p2.Equal(p3) {
		t.Errorf("p1.Equal(p3) = true, want false")
	}
}
