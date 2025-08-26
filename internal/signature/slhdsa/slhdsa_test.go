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

package slhdsa

import (
	"slices"
	"testing"
)

func TestDerivedParameters(t *testing.T) {
	for _, tc := range []struct {
		name     string
		par      *params
		wantW    uint32
		wantLen1 uint32
		wantLen2 uint32
		wantLen  uint32
	}{
		{"SLH-DSA-SHA2-128s", SLH_DSA_SHA2_128s, 16, 32, 3, 35},
		{"SLH-DSA-SHAKE-128s", SLH_DSA_SHAKE_128s, 16, 32, 3, 35},
		{"SLH-DSA-SHA2-128f", SLH_DSA_SHA2_128f, 16, 32, 3, 35},
		{"SLH-DSA-SHAKE-128f", SLH_DSA_SHAKE_128f, 16, 32, 3, 35},
		{"SLH-DSA-SHA2-192s", SLH_DSA_SHA2_192s, 16, 48, 3, 51},
		{"SLH-DSA-SHAKE-192s", SLH_DSA_SHAKE_192s, 16, 48, 3, 51},
		{"SLH-DSA-SHA2-192f", SLH_DSA_SHA2_192f, 16, 48, 3, 51},
		{"SLH-DSA-SHAKE-192f", SLH_DSA_SHAKE_192f, 16, 48, 3, 51},
		{"SLH-DSA-SHA2-256s", SLH_DSA_SHA2_256s, 16, 64, 3, 67},
		{"SLH-DSA-SHAKE-256s", SLH_DSA_SHAKE_256s, 16, 64, 3, 67},
		{"SLH-DSA-SHA2-256f", SLH_DSA_SHA2_256f, 16, 64, 3, 67},
		{"SLH-DSA-SHAKE-256f", SLH_DSA_SHAKE_256f, 16, 64, 3, 67},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantW != tc.par.w {
				t.Errorf("w = %v, want %v", tc.par.w, tc.wantW)
			}
			if tc.wantLen1 != tc.par.len1 {
				t.Errorf("len1 = %v, want %v", tc.par.len1, tc.wantLen1)
			}
			if tc.wantLen2 != tc.par.len2 {
				t.Errorf("len2 = %v, want %v", tc.par.len2, tc.wantLen2)
			}
			if tc.wantLen != tc.par.len {
				t.Errorf("len = %v, want %v", tc.par.len, tc.wantLen)
			}
		})
	}
}

func TestHashParamsKat(t *testing.T) {
	for _, tc := range []struct {
		name string
		par  *params
		vec  hashTestVector
	}{
		{"SLH-DSA-SHA2-128s", SLH_DSA_SHA2_128s, hashTestVectorSha2C1n16m30},
		{"SLH-DSA-SHAKE-128s", SLH_DSA_SHAKE_128s, hashTestVectorShaken16m30},
		{"SLH-DSA-SHA2-128f", SLH_DSA_SHA2_128f, hashTestVectorSha2C1n16m34},
		{"SLH-DSA-SHAKE-128f", SLH_DSA_SHAKE_128f, hashTestVectorShaken16m34},
		{"SLH-DSA-SHA2-192s", SLH_DSA_SHA2_192s, hashTestVectorSha2C35n24m39},
		{"SLH-DSA-SHAKE-192s", SLH_DSA_SHAKE_192s, hashTestVectorShaken24m39},
		{"SLH-DSA-SHA2-192f", SLH_DSA_SHA2_192f, hashTestVectorSha2C35n24m42},
		{"SLH-DSA-SHAKE-192f", SLH_DSA_SHAKE_192f, hashTestVectorShaken24m42},
		{"SLH-DSA-SHA2-256s", SLH_DSA_SHA2_256s, hashTestVectorSha2C35n32m47},
		{"SLH-DSA-SHAKE-256s", SLH_DSA_SHAKE_256s, hashTestVectorShaken32m47},
		{"SLH-DSA-SHA2-256f", SLH_DSA_SHA2_256f, hashTestVectorSha2C35n32m49},
		{"SLH-DSA-SHAKE-256f", SLH_DSA_SHAKE_256f, hashTestVectorShaken32m49},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.par.n != tc.vec.n {
				t.Fatalf("tc.par.n = %v, want %v", tc.par.n, tc.vec.n)
			}
			if tc.par.m != tc.vec.m {
				t.Fatalf("tc.par.m = %v, want %v", tc.par.m, tc.vec.m)
			}
			hMsg := tc.par.hHMsg(tc.vec.r, tc.vec.pkSeed, tc.vec.pkRoot, tc.vec.msg)
			if !slices.Equal(hMsg, tc.vec.wantHMsg) {
				t.Errorf("tc.hMsg() = %v, want %v", hMsg, tc.vec.wantHMsg)
			}
			prf := tc.par.hPrf(tc.vec.pkSeed, tc.vec.skSeed, newAddress())
			if !slices.Equal(prf, tc.vec.wantPrf) {
				t.Errorf("tc.prf() = %v, want %v", prf, tc.vec.wantPrf)
			}
			prfMsg := tc.par.hPrfMsg(tc.vec.skPrf, tc.vec.optRand, tc.vec.msg)
			if !slices.Equal(prfMsg, tc.vec.wantPrfMsg) {
				t.Errorf("tc.prfMsg() = %v, want %v", prfMsg, tc.vec.wantPrfMsg)
			}
			f := tc.par.hF(tc.vec.pkSeed, newAddress(), tc.vec.msg)
			if !slices.Equal(f, tc.vec.wantF) {
				t.Errorf("tc.f() = %v, want %v", f, tc.vec.wantF)
			}
			h := tc.par.hH(tc.vec.pkSeed, newAddress(), tc.vec.msg)
			if !slices.Equal(h, tc.vec.wantH) {
				t.Errorf("tc.h() = %v, want %v", h, tc.vec.wantH)
			}
			tl := tc.par.hTl(tc.vec.pkSeed, newAddress(), tc.vec.msg)
			if !slices.Equal(tl, tc.vec.wantTl) {
				t.Errorf("tc.tl() = %v, want %v", tl, tc.vec.wantTl)
			}
		})
	}
}
