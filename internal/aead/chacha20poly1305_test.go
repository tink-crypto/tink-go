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

package aead_test

import (
	"math"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"github.com/tink-crypto/tink-go/v2/internal/aead"
)

func TestCheckChaCha20Poly1305PlaintextSize(t *testing.T) {
	tests := []struct {
		name          string
		plaintextSize int
		wantErr       bool
	}{
		{
			name:          "plaintext too long",
			plaintextSize: math.MaxInt - chacha20poly1305.NonceSize - chacha20poly1305.Overhead + 1,
			wantErr:       true,
		},
		{
			name:          "plaintext ok",
			plaintextSize: math.MaxInt - chacha20poly1305.NonceSize - chacha20poly1305.Overhead,
			wantErr:       false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := aead.CheckChaCha20Poly1305PlaintextSize(tc.plaintextSize)
			if got, want := (err != nil), tc.wantErr; got != want {
				t.Errorf("aead.CheckChaCha20Poly1305PlaintextSize(%d) err = %v, want %v", tc.plaintextSize, err, tc.wantErr)
				t.Errorf("aead.CheckChaCha20Poly1305PlaintextSize(plaintext) (err == nil) = %v, want %v", got, want)
			}
		})
	}
}
