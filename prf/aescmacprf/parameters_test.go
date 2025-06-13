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

package aescmacprf_test

import (
	"testing"

	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/prf/aescmacprf"
)

func TestParametersValid(t *testing.T) {
	params256, err := aescmacprf.NewParameters(32)
	if err != nil {
		t.Errorf("aescmacprf.NewParameters(32) failed: %v", err)
	}
	if params256.KeySizeInBytes() != 32 {
		t.Errorf("params256.KeySizeInBytes() = %d, want 32", params256.KeySizeInBytes())
	}
	params128, err := aescmacprf.NewParameters(16)
	if err != nil {
		t.Errorf("aescmacprf.NewParameters(16) failed: %v", err)
	}
	if params128.KeySizeInBytes() != 16 {
		t.Errorf("params128.KeySizeInBytes() = %d, want 16", params128.KeySizeInBytes())
	}
}

func TestParametersInvalidKeySize(t *testing.T) {
	if _, err := aescmacprf.NewParameters(17); err == nil {
		t.Errorf("aescmacprf.NewParameters(17) succeeded, expected error")
	}
}

func TestParametersEquals(t *testing.T) {
	params1, err := aescmacprf.NewParameters(32)
	if err != nil {
		t.Fatalf("aescmacprf.NewParameters(32) failed: %v", err)
	}
	params2, err := aescmacprf.NewParameters(32)
	if err != nil {
		t.Fatalf("aescmacprf.NewParameters(32) failed: %v", err)
	}
	if !params1.Equal(&params2) {
		t.Errorf("Equal() returned false, expected true")
	}

	params1, err = aescmacprf.NewParameters(16)
	if err != nil {
		t.Fatalf("aescmacprf.NewParameters(16) failed: %v", err)
	}
	params2, err = aescmacprf.NewParameters(16)
	if err != nil {
		t.Fatalf("aescmacprf.NewParameters(16) failed: %v", err)
	}
	if !params1.Equal(&params2) {
		t.Errorf("Equal() returned false, expected true")
	}
}

type stubParameters struct{}

var _ key.Parameters = (*stubParameters)(nil)

func (p *stubParameters) Equal(other key.Parameters) bool { return false }

func (p *stubParameters) HasIDRequirement() bool { return false }

func TestParametersNotEquals(t *testing.T) {
	params1, err := aescmacprf.NewParameters(32)
	if err != nil {
		t.Fatalf("aescmacprf.NewParameters(32) failed: %v", err)
	}
	params2, err := aescmacprf.NewParameters(16)
	if err != nil {
		t.Fatalf("aescmacprf.NewParameters(16) failed: %v", err)
	}
	if params1.Equal(&params2) {
		t.Errorf("Equal() returned true, expected false")
	}

	if params1.Equal(&stubParameters{}) {
		t.Errorf("Equal() returned true, expected false")
	}
}
