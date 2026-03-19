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

func TestNewParameters(t *testing.T) {
	for _, ca := range []compositemldsa.ClassicalAlgorithm{
		compositemldsa.Ed25519,
		compositemldsa.ECDSAP256,
		compositemldsa.ECDSAP384,
		compositemldsa.ECDSAP521,
		compositemldsa.RSA3072PSS,
		compositemldsa.RSA4096PSS,
		compositemldsa.RSA3072PKCS1,
		compositemldsa.RSA4096PKCS1,
		compositemldsa.UnknownAlgorithm,
	} {
		for _, inst := range []compositemldsa.MLDSAInstance{
			compositemldsa.MLDSA65,
			compositemldsa.MLDSA87,
			compositemldsa.UnknownInstance,
		} {
			for _, variant := range []compositemldsa.Variant{
				compositemldsa.VariantTink,
				compositemldsa.VariantNoPrefix,
				compositemldsa.VariantUnknown,
			} {
				params, err := compositemldsa.NewParameters(ca, inst, variant)
				if ca == compositemldsa.UnknownAlgorithm {
					if err == nil {
						t.Errorf("compositemldsa.NewParameters(%v, %v, %v) err = nil, want error", ca, inst, variant)
					}
					continue
				}
				if variant == compositemldsa.VariantUnknown {
					if err == nil {
						t.Errorf("compositemldsa.NewParameters(%v, %v, %v) err = nil, want error", ca, inst, variant)
					}
					continue
				}
				if inst == compositemldsa.UnknownInstance {
					if err == nil {
						t.Errorf("compositemldsa.NewParameters(%v, %v, %v) err = nil, want error", ca, inst, variant)
					}
					continue
				}
				if err != nil {
					t.Errorf("compositemldsa.NewParameters(%v, %v, %v) err = %v, want nil", ca, inst, variant, err)
				}
				if got := params.ClassicalAlgorithm(); got != ca {
					t.Errorf("params.ClassicalAlgorithm() = %v, want %v", got, ca)
				}
				if got := params.MLDSAInstance(); got != inst {
					t.Errorf("params.MlDsaInstance() = %v, want %v", got, inst)
				}
				if got := params.Variant(); got != variant {
					t.Errorf("params.Variant() = %v, want %v", got, variant)
				}
			}
		}
	}
}

func TestParametersEqual(t *testing.T) {
	for _, ca := range []compositemldsa.ClassicalAlgorithm{
		compositemldsa.Ed25519,
		compositemldsa.ECDSAP256,
	} {
		for _, inst := range []compositemldsa.MLDSAInstance{
			compositemldsa.MLDSA65,
			compositemldsa.MLDSA87,
		} {
			t.Run(fmt.Sprintf("%v/%v", ca, inst), func(t *testing.T) {
				tinkParams, err := compositemldsa.NewParameters(ca, inst, compositemldsa.VariantTink)
				if err != nil {
					t.Fatalf("NewParameters(ca, inst, compositemldsa.VariantTink) err = %v", err)
				}
				noPrefixParams, err := compositemldsa.NewParameters(ca, inst, compositemldsa.VariantNoPrefix)
				if err != nil {
					t.Fatalf("NewParameters(ca, inst, compositemldsa.VariantNoPrefix) err = %v", err)
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
	p2, err := compositemldsa.NewParameters(compositemldsa.ECDSAP256, compositemldsa.MLDSA65, compositemldsa.VariantTink)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if p1.Equal(p2) {
		t.Errorf("p1.Equal(p2) = true, want false")
	}
	p3, err := compositemldsa.NewParameters(compositemldsa.Ed25519, compositemldsa.MLDSA87, compositemldsa.VariantTink)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if p1.Equal(p3) {
		t.Errorf("p1.Equal(p3) = true, want false")
	}
}
