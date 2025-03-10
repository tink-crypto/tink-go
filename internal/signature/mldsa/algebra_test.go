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

package mldsa

import (
	"math/big"
	mathrand "math/rand/v2"
	"testing"
)

// The modulus is too large to test all possible values in a reasonable amount of time.
// Instead, we will test a random subset of values every time this test runs.
const numTestValues = 10000

// Possible values for gamma2 for all possible ML-DSA parameters.
var gamma2TestValues = [2]uint32{
	(q - 1) / 88,
	(q - 1) / 32,
}

func TestReduceOnce(t *testing.T) {
	for i := 0; i < 2*q; i++ {
		got := rZq(i).reduceOnce()
		exp := rZq(i % q)
		if got != exp {
			t.Fatalf("rZq(%v).reduceOnce() = %v, want %v", i, got, exp)
		}
	}
}

func TestAdd(t *testing.T) {
	for i := 0; i < numTestValues; i++ {
		a := mathrand.IntN(q)
		b := mathrand.IntN(q)
		got := rZq(a).add(rZq(b))
		exp := rZq((a + b) % q)
		if got != exp {
			t.Fatalf("rZq(%v).add(rZq(%v)) = %v, want %v", a, b, got, exp)
		}
	}
}

func TestNeg(t *testing.T) {
	for i := 0; i < q; i++ {
		got := rZq(i).neg()
		exp := rZq((q - i) % q)
		if got != exp {
			t.Fatalf("rZq(%v).neg() = %v, want %v", i, got, exp)
		}
	}
}

func TestSub(t *testing.T) {
	for i := 0; i < numTestValues; i++ {
		a := mathrand.IntN(q)
		b := mathrand.IntN(q)
		got := rZq(a).sub(rZq(b))
		exp := rZq((a + q - b) % q)
		if got != exp {
			t.Fatalf("rZq(%v).sub(rZq(%v)) = %v, want %v", a, b, got, exp)
		}
	}
}

func TestMul(t *testing.T) {
	for i := 0; i < numTestValues; i++ {
		a := mathrand.IntN(q)
		b := mathrand.IntN(q)
		got := rZq(a).mul(rZq(b))
		bigA := big.NewInt(int64(a))
		bigB := big.NewInt(int64(b))
		bigQ := big.NewInt(int64(q))
		exp := new(big.Int).Mul(bigA, bigB)
		exp.Mod(exp, bigQ)
		if int64(got) != exp.Int64() {
			t.Fatalf("rZq(%v).mul(rZq(%v)) = %v, want %v", a, b, got, exp)
		}
	}
}

func TestPower2Round(t *testing.T) {
	for i := 0; i < q; i++ {
		exp := rZq(i)
		r1, r0 := exp.power2Round()
		got := r1.scalePower2().add(r0)
		if got != exp {
			t.Fatalf("rZq(%v).power2Round() = %v, want %v", exp, got, exp)
		}
	}
}

func TestDivBy2Gamma2(t *testing.T) {
	for _, gamma2 := range gamma2TestValues {
		for i := 0; i < q; i++ {
			exp := uint32(i) / (2 * gamma2)
			got := divBy2Gamma2(uint32(i), gamma2)
			if got != exp {
				t.Fatalf("divBy2Gamma2(%v, %v) = %v, want %v", i, gamma2, got, exp)
			}
		}
	}
}

func TestDecompose(t *testing.T) {
	for _, gamma2 := range gamma2TestValues {
		for i := 0; i < q; i++ {
			exp := rZq(i)
			r1, r0 := exp.decompose(gamma2)
			got := r1.mul(rZq(2 * gamma2)).add(r0)
			if got != exp {
				t.Fatalf("rZq(%v).decompose(%v) = %v, want %v", exp, gamma2, got, exp)
			}
		}
	}
}

func TestUseHint(t *testing.T) {
	for _, gamma2 := range gamma2TestValues {
		for i := 0; i < q; i++ {
			a := rZq(i)
			r1, r0 := a.decompose(gamma2)
			if a.useHint(gamma2, 0) != r1 {
				t.Fatalf("rZq(%v).useHint(%v, 0) != %v", a, gamma2, a)
			}
			m := (q - 1) / (gamma2 << 1)
			th := rZq(gamma2).neg()
			exp := uint32(r1)
			if r0 > rZq(0) && r0 < th {
				// Unsigned inc-mod.
				if exp == m-1 {
					exp = 0
				} else {
					exp = exp + 1
				}
			}
			if r0 >= th {
				// Unsigned dec-mod.
				if exp == 0 {
					exp = m - 1
				} else {
					exp = exp - 1
				}
			}
			got := a.useHint(gamma2, 1)
			if got != rZq(exp) {
				t.Fatalf("rZq(%v).useHint(%v, 1) = %v, want %v", a, gamma2, got, exp)
			}
		}
	}
}

func TestCenteredAbs(t *testing.T) {
	for i := 0; i < q; i++ {
		num := rZq(i)
		exp := uint32(num)
		if (q-1)/2 <= exp {
			exp = q - exp
		}
		got := num.centeredAbs()
		if got != exp {
			t.Fatalf("rZq(%v).centeredAbs() = %v, want %v", num, got, exp)
		}
	}
}

func TestCenteredMax(t *testing.T) {
	for i := 0; i < numTestValues; i++ {
		a := rZq(mathrand.IntN(q))
		b := rZq(mathrand.IntN(q))
		exp := a
		if a.centeredAbs() < b.centeredAbs() {
			exp = b
		}
		got := a.centeredMax(b)
		if got != exp {
			t.Fatalf("rZq(%v).centeredMax(rZq(%v)) = %v, want %v", a, b, got, exp)
		}
	}
}

func randomPoly() *poly {
	res := poly{}
	for i := range res {
		res[i] = rZq(mathrand.IntN(q))
	}
	return &res
}

func TestInfinityNormMax(t *testing.T) {
	for i := 0; i < numTestValues; i++ {
		p := randomPoly()
		p[0] = rZq((q - 1) / 2)
		exp := p[0].centeredAbs()
		got := p.infinityNorm()
		if got != exp {
			t.Fatalf("p.infinityNorm() = %v, want %v", got, exp)
		}
	}
}

func comparePoly(p, q *poly) bool {
	if len(p) != len(q) {
		return false
	}
	for i := range p {
		if p[i] != q[i] {
			return false
		}
	}
	return true
}

func TestNttInverseNtt(t *testing.T) {
	for i := 0; i < numTestValues; i++ {
		exp := randomPoly()
		expNtt := exp.ntt()
		got := expNtt.intt()
		if !comparePoly(exp, got) {
			t.Fatalf("expNtt.intt() = %v, want %v", got, exp)
		}
	}
}

func TestNumOnes(t *testing.T) {
	exp := 0
	v := makeZeroVector(degree)
	for i := range v {
		for j := range v[i] {
			if mathrand.IntN(2) == 0 {
				v[i][j] = rZq(0)
			} else {
				v[i][j] = rZq(1)
				exp++
			}
		}
	}
	got := v.numOnes()
	if got != exp {
		t.Fatalf("v.numOnes() = %v, want %v", got, exp)
	}
}
