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

package noncebased

import "testing"

func TestGrownSegmentBufferSize(t *testing.T) {
	const limit = 1 << 20
	testcases := []struct {
		cur, needed, limit, want int
	}{
		{cur: 4096, limit: limit, want: 32768},
		{cur: 32768, limit: limit, want: 262144},
		// A step from 262144 would reach 2 MiB, at least three quarters of
		// the limit, so the size jumps to the limit instead.
		{cur: 262144, limit: limit, want: limit},
		// Growth from a size off the fixed sequence (left by a needed
		// floor) continues along the sequence.
		{cur: 98303, limit: limit, want: 262144},
		{cur: 262143, limit: limit, want: 262144},
		{cur: 300000, limit: limit, want: limit},
		// A limit one byte above a power of two (the Reader's lookahead
		// byte) must not cost a full-sized step for that final byte.
		{cur: 4096, limit: 4097, want: 4097},
		{cur: 131072, limit: 1<<20 + 1, want: 262144},
		{cur: 262144, limit: 1<<20 + 1, want: 1<<20 + 1},
		// The growth step is a floor: pending data below it changes
		// nothing.
		{cur: 4096, needed: 10000, limit: limit, want: 32768},
		// Pending data beyond the growth step is allocated in one step.
		{cur: 4096, needed: 500000, limit: limit, want: 500000},
		// Pending data at or beyond three quarters of the limit jumps to
		// the limit, as a growth step would.
		{cur: 4096, needed: 786432, limit: limit, want: limit},
		{cur: 4096, needed: 786433, limit: limit, want: limit},
		{cur: 4096, needed: 40 << 20, limit: limit, want: limit},
	}
	for _, tc := range testcases {
		if got := grownSegmentBufferSize(tc.cur, tc.needed, tc.limit); got != tc.want {
			t.Errorf("grownSegmentBufferSize(%d, %d, %d) = %d, want %d", tc.cur, tc.needed, tc.limit, got, tc.want)
		}
	}
}

func TestInitialSegmentBufferSizeFor(t *testing.T) {
	testcases := []struct {
		limit, want int
	}{
		{limit: 1, want: 1},
		{limit: 4095, want: 4095},
		{limit: 4096, want: 4096},
		// A limit only slightly above the initial size (such as a 4 KiB
		// ciphertext segment plus the lookahead byte) is allocated in full
		// rather than grown by a single step.
		{limit: 4097, want: 4097},
		{limit: 5461, want: 5461},
		{limit: 5462, want: 4096},
		{limit: 1 << 20, want: 4096},
	}
	for _, tc := range testcases {
		if got := initialSegmentBufferSizeFor(tc.limit); got != tc.want {
			t.Errorf("initialSegmentBufferSizeFor(%d) = %d, want %d", tc.limit, got, tc.want)
		}
	}
}

// TestGrowthSequence checks that growth from the initial size always
// progresses, never overshoots the limit, and takes a bounded number of
// steps.
func TestGrowthSequence(t *testing.T) {
	for limit := 1; limit < 6000; limit++ {
		cur := initialSegmentBufferSizeFor(limit)
		for steps := 0; cur < limit; steps++ {
			next := grownSegmentBufferSize(cur, 0, limit)
			if next <= cur || next > limit {
				t.Fatalf("limit=%d cur=%d: grownSegmentBufferSize = %d", limit, cur, next)
			}
			if steps > 4 {
				t.Fatalf("limit=%d: too many growth steps", limit)
			}
			cur = next
		}
	}
	limit := 1<<20 + 1
	var sizes []int
	for cur := initialSegmentBufferSizeFor(limit); ; cur = grownSegmentBufferSize(cur, 0, limit) {
		sizes = append(sizes, cur)
		if cur == limit {
			break
		}
	}
	want := []int{4096, 32768, 262144, limit}
	if len(sizes) != len(want) {
		t.Fatalf("growth sequence = %v, want %v", sizes, want)
	}
	for i := range want {
		if sizes[i] != want[i] {
			t.Fatalf("growth sequence = %v, want %v", sizes, want)
		}
	}
}
