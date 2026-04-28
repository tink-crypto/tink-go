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

package mldsa

import (
	"encoding/hex"
	"strconv"
	"testing"

	"golang.org/x/crypto/sha3"
)

// CCTV accumulated test vectors.
// See https://github.com/C2SP/CCTV/tree/main/ML-DSA/accumulated.

// TestCCTVAccumulated applies the CCTV accumulated random key generation +
// signature vectors. Seeds are drawn from one SHAKE128 instance and the
// derived public key plus the deterministic signature of an empty message
// are absorbed into a second SHAKE128 instance; the squeezed 32-byte
// output is the test value.
//
// We only include the 100-iteration vectors in the test suite.
// The 10 000 000-iteration vectors take a few minutes per parameter set.
// The 60 000 000-iteration vectors take several CPU-hours per parameter set.
func TestCCTVAccumulated(t *testing.T) {
	vectors := []struct {
		name       string
		params     *params
		iterations int
		expected   string
	}{
		{"ML-DSA-44/100", MLDSA44, 100, "d51148e1f9f4fa1a723a6cf42e25f2a99eb5c1b378b3d2dbbd561b1203beeae4"},
		{"ML-DSA-65/100", MLDSA65, 100, "8358a1843220194417cadbc2651295cd8fc65125b5a5c1a239a16dc8b57ca199"},
		{"ML-DSA-87/100", MLDSA87, 100, "8c3ad714777622b8f21ce31bb35f71394f23bc0fcf3c78ace5d608990f3b061b"},
	}
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()
			got := runCCTVAccumulated(v.params, v.iterations)
			if got != v.expected {
				t.Errorf("got %s, want %s", got, v.expected)
			}
		})
	}
}

func runCCTVAccumulated(par *params, iterations int) string {
	source := sha3.NewShake128()
	acc := sha3.NewShake128()
	var seed [SecretKeySeedSize]byte
	for i := 0; i < iterations; i++ {
		source.Read(seed[:])
		pk, sk := par.KeyGenFromSeed(seed)
		sig, err := sk.SignDeterministic(nil, nil)
		if err != nil {
			panic(err)
		}
		acc.Write(pk.Encode())
		acc.Write(sig)
	}
	var out [32]byte
	acc.Read(out[:])
	return hex.EncodeToString(out[:])
}

// TestCCTVFieldOps applies the CCTV exhaustive field-operations vector.
// For each r in [0, q), 12 newline-terminated ASCII decimals are absorbed
// into a SHAKE128 instance: the centered mod q value, its absolute value,
// the Power2Round (r1, r0) pair (with r0 in unsigned [0, q) form), and
// then for each of the two γ₂ values the HighBits, UseHint(1, r),
// LowBits (signed centered), and |LowBits|.
func TestCCTVFieldOps(t *testing.T) {
	// https://github.com/C2SP/CCTV/blob/main/ML-DSA/accumulated/README.md#field-operation-tests
	const expected = "f930663417278156ab05d940294a77210a809c924d8ab63ec72f4526247602c7"

	gammas := [2]uint32{MLDSA44.gamma2, MLDSA65.gamma2}
	acc := sha3.NewShake128()
	buf := make([]byte, 0, 256)
	w := func(s int64) {
		buf = strconv.AppendInt(buf, s, 10)
		buf = append(buf, '\n')
	}
	// Reuse a single zeroed poly: by writing the value of interest into
	// p[0] (and leaving the other 255 coefficients at 0), p.infinityNorm()
	// returns the per-coefficient |·mod± q| of that value.
	var p poly
	infNorm := func(a rZq) uint32 {
		p[0] = a
		return p.infinityNorm()
	}

	for r := uint32(0); r < q; r++ {
		a := rZq(r)
		w(centeredMod(a))
		w(int64(infNorm(a)))

		// Power2Round's r0 is written in unsigned [0, q) form, which is
		// what tink-go's power2Round already returns.
		r1, r0 := a.power2Round()
		w(int64(r1))
		w(int64(r0))

		for _, g := range gammas {
			r1d, r0d := a.decompose(g)
			w(int64(r1d))
			w(int64(a.useHint(g, rZq(1))))
			// Decompose's r0 is written in signed centered form.
			w(centeredMod(r0d))
			w(int64(infNorm(r0d)))
		}

		acc.Write(buf)
		buf = buf[:0]
	}

	var out [32]byte
	acc.Read(out[:])
	if got := hex.EncodeToString(out[:]); got != expected {
		t.Errorf("got %s, want %s", got, expected)
	}
}

// centeredMod returns r mod± q as a signed integer, where q is odd so
// the result is in [-(q-1)/2, (q-1)/2]. See FIPS 204 §2.3. tink-go
// itself only ever needs |r mod± q| (centeredAbs), not the sign, so it
// has no equivalent function to test directly.
func centeredMod(a rZq) int64 {
	if uint32(a) <= (q-1)/2 {
		return int64(a)
	}
	return int64(a) - int64(q)
}
