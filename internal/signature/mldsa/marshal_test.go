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
	"bytes"
	"crypto/rand"
	mathrand "math/rand/v2"
	"testing"
)

func randomPolyN(n int) *poly {
	res := poly{}
	for i := range res {
		res[i] = rZq(mathrand.IntN(n))
	}
	return &res
}

func TestPolySimpleBitPackUnpack(t *testing.T) {
	for i := 0; i < numTestValues; i++ {
		// Generate random polynomial with random coefficient number of bits [1, qBits].
		bits := 1 + mathrand.IntN(qBits)
		exp := randomPolyN(1 << bits)
		got := simpleBitUnpackPoly(exp.simpleBitPack(bits), bits)
		if !comparePoly(exp, got) {
			t.Fatalf("p.encode(%v).decodePoly(...) = %v, want %v", bits, got, exp)
		}
	}
}

func TestPolyBitPackUnpack(t *testing.T) {
	for i := 0; i < numTestValues; i++ {
		// Generate random polynomial with random coefficient number of bits [1, qBits].
		bits := 1 + mathrand.IntN(qBits)
		a := 1 << (bits - 1)
		exp := randomPolyN(a)
		got := bitUnpackPoly(exp.bitPack(rZq(a), bits), rZq(a), bits)
		if !comparePoly(exp, got) {
			t.Fatalf("p.encodeSigned(%v, %v).decodePolySigned(...) = %v, want %v", a, bits, got, exp)
		}
	}
}

// Note that numOnes is strictly less than a scalar's length.
func randomVectorHint(par *params, numOnes int) vector {
	if numOnes > degree {
		panic("numOnes must be <= degree")
	}
	res := makeZeroVector(par.k)
	// Set the first numOnes coefficients to 1.
	for i := 0; i < numOnes; i++ {
		res[0][i] = rZq(1)
	}
	// And then Fisher-Yates shuffle.
	mathrand.Shuffle(len(res)*len(res[0]), func(i, j int) {
		k := i / len(res[0])
		l := i % len(res[0])
		m := j / len(res[0])
		n := j % len(res[0])
		res[k][l], res[m][n] = res[m][n], res[k][l]
	})
	return res
}

func compareVector(u, v vector) bool {
	if len(u) != len(v) {
		return false
	}
	for i := range u {
		if !comparePoly(u[i], v[i]) {
			return false
		}
	}
	return true
}

func TestVectorHintBitPackUnpack(t *testing.T) {
	pars := []struct {
		name string
		par  *params
	}{
		{"MLDSA44", MLDSA44},
		{"MLDSA65", MLDSA65},
		{"MLDSA87", MLDSA87},
	}
	for _, par := range pars {
		for i := 0; i < numTestValues; i++ {
			exp := randomVectorHint(par.par, par.par.omega)
			got, err := par.par.hintBitUnpackVector(exp.hintBitPack(par.par))
			if err != nil {
				t.Errorf("decodeVector(%v) failed: %v", par.name, err)
			}
			if !compareVector(exp, got) {
				t.Errorf("decodeVector(%v) failed", par.name)
			}
		}
	}
}

func onesVectorHint(par *params, wantNumOnes int) vector {
	res := makeZeroVector(par.k)
	numOnes := 0
	for i := range res {
		for j := range res[i] {
			if numOnes < wantNumOnes {
				res[i][j] = rZq(1)
				numOnes++
			} else {
				res[i][j] = rZq(0)
			}
		}
	}
	return res
}

func TestHintBitUnpackOverflowVectorFails(t *testing.T) {
	pars := []struct {
		name string
		par  *params
	}{
		{"MLDSA44", MLDSA44},
		{"MLDSA65", MLDSA65},
		{"MLDSA87", MLDSA87},
	}
	for _, par := range pars {
		exp := onesVectorHint(par.par, par.par.omega+1)
		_, err := par.par.hintBitUnpackVector(exp.hintBitPack(par.par))
		if err == nil {
			t.Errorf("decodeVector(%v) succeeded, want error", par.name)
		}
	}
}

func TestHintBitUnpackInvalidPaddingVectorFails(t *testing.T) {
	pars := []struct {
		name string
		par  *params
	}{
		{"MLDSA44", MLDSA44},
		{"MLDSA65", MLDSA65},
		{"MLDSA87", MLDSA87},
	}
	for _, par := range pars {
		exp := onesVectorHint(par.par, 1)
		enc := exp.hintBitPack(par.par)
		enc[1] = byte(255)
		_, err := par.par.hintBitUnpackVector(enc)
		if err == nil {
			t.Errorf("decodeVector(%v) succeeded, want error", par.name)
		}
	}
}

func comparePublicKey(u, v *PublicKey) bool {
	return bytes.Equal(u.rho[:], v.rho[:]) &&
		compareVector(u.t1, v.t1) &&
		bytes.Equal(u.tr[:], v.tr[:]) &&
		u.par == v.par
}

func compareSecretKey(u, v *SecretKey) bool {
	return bytes.Equal(u.rho[:], v.rho[:]) &&
		bytes.Equal(u.kK[:], v.kK[:]) &&
		bytes.Equal(u.tr[:], v.tr[:]) &&
		compareVector(u.s1, v.s1) &&
		compareVector(u.s2, v.s2) &&
		compareVector(u.t0, v.t0) &&
		u.par == v.par
}

func TestKeyEncodeDecode(t *testing.T) {
	pars := []struct {
		name string
		par  *params
	}{
		{"MLDSA44", MLDSA44},
		{"MLDSA65", MLDSA65},
		{"MLDSA87", MLDSA87},
	}
	for _, par := range pars {
		for j := 0; j < 100; j++ {
			var seed [32]byte
			rand.Read(seed[:])
			pk, sk := par.par.KeyGen()
			pkDec, err := par.par.DecodePublicKey(pk.Encode())
			if err != nil {
				t.Errorf("PkDecode(%v) failed: %v", par.name, err)
			}
			if !comparePublicKey(pk, pkDec) {
				t.Errorf("PkDecode(%v) = %v, want %v", par.name, pkDec, pk)
			}
			skDec, err := par.par.DecodeSecretKey(sk.Encode())
			if err != nil {
				t.Errorf("SkDecode(%v) failed: %v", par.name, err)
			}
			if !compareSecretKey(sk, skDec) {
				t.Errorf("SkDecode(%v) = %v, want %v", par.name, skDec, sk)
			}
		}
	}
}
