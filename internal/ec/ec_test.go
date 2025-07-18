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

package ec_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/internal/ec"
)

func TestBigIntBytesToFixedSizeBuffer(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input []byte
		size  int
		want  []byte
	}{
		{
			name:  "same size",
			input: []byte{0x01, 0x02, 0x03, 0x04},
			size:  4,
			want:  []byte{0x01, 0x02, 0x03, 0x04},
		},
		{
			name:  "input smaller than size",
			input: []byte{0x01, 0x02, 0x03, 0x04},
			size:  5,
			want:  []byte{0x00, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:  "input larger than size",
			input: []byte{0x00, 0x00, 0x03, 0x04, 0x05, 0x06},
			size:  4,
			want:  []byte{0x03, 0x04, 0x05, 0x06},
		},
		{
			name:  "input larger than size with leading zeros",
			input: []byte{0x00, 0x00, 0x03, 0x04, 0x05, 0x06},
			size:  5,
			want:  []byte{0x00, 0x03, 0x04, 0x05, 0x06},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ec.BigIntBytesToFixedSizeBuffer(tc.input, tc.size)
			if err != nil {
				t.Fatalf("ec.BigIntBytesToFixedSizeBuffer(%v, %v) err = %v, want nil", tc.input, tc.size, err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ec.BigIntBytesToFixedSizeBuffer(%v, %v) returned unexpected diff (-want +got):\n%s", tc.input, tc.size, diff)
			}
		})
	}
}

func TestBigIntBytesToFixedSizeBuffer_FailsWhenInputTooLarge(t *testing.T) {
	if _, err := ec.BigIntBytesToFixedSizeBuffer([]byte{0x01, 0x02}, 1); err == nil {
		t.Errorf("ec.BigIntBytesToFixedSizeBuffer() err = nil, want error")
	}
}
