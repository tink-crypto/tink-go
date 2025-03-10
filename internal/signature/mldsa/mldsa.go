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

// Package mldsa implements ML-DSA as specified in NIST FIPS 204 (https://doi.org/10.6028/NIST.FIPS.204).
package mldsa

import (
	"math/bits"
)

const (
	// Base ring modulus.
	q = 8380417
	// Base ring storage bits.
	qBits = 23
	// Root of unity modulo q.
	zeta = 1753
	// Inverse of 256 modulo q.
	inv256 = 8347681
	// Degree of polynomial modulus (= X^256 + 1).
	degree = 256

	// Dropped bits.
	d = 13
)

type params struct {
	// ML-DSA parameters (see https://doi.org/10.6028/NIST.FIPS.204).
	tau        int
	lambda     int
	log2Gamma1 int
	gamma2     uint32
	k          int
	l          int
	eta        int
	omega      int
	// Precomputed derived parameters.
	etaBits int
	w1Bits  int
}

type paramsOpts struct {
	tau        int
	lambda     int
	log2Gamma1 int
	invGamma2  uint32
	k          int
	l          int
	eta        int
	omega      int
}

func newParams(par paramsOpts) *params {
	gamma2 := (q - 1) / par.invGamma2
	etaBits := bits.Len(uint(2 * par.eta))
	w1Bits := bits.Len(uint((q-1)/(2*gamma2) - 1))
	return &params{par.tau, par.lambda, par.log2Gamma1, gamma2, par.k, par.l, par.eta, par.omega, etaBits, w1Bits}
}

var (
	// MLDSA44 defines parameters for ML-DSA-44.
	MLDSA44 = newParams(paramsOpts{
		tau:        39,
		lambda:     128,
		log2Gamma1: 17,
		invGamma2:  88,
		k:          4,
		l:          4,
		eta:        2,
		omega:      80,
	})
	// MLDSA65 defines parameters for ML-DSA-65.
	MLDSA65 = newParams(paramsOpts{
		tau:        49,
		lambda:     192,
		log2Gamma1: 19,
		invGamma2:  32,
		k:          6,
		l:          5,
		eta:        4,
		omega:      55,
	})
	// MLDSA87 defines parameters for ML-DSA-87.
	MLDSA87 = newParams(paramsOpts{
		tau:        60,
		lambda:     256,
		log2Gamma1: 19,
		invGamma2:  32,
		k:          8,
		l:          7,
		eta:        2,
		omega:      75,
	})
)

// publicKey represents a ML-DSA public key.
type publicKey struct {
	rho [32]byte
	t1  vector
	// Cached public key hash.
	tr [64]byte
	// Corresponding parameters.
	par *params
}

// secretKey represents a ML-DSA secret key.
type secretKey struct {
	rho [32]byte
	kK  [32]byte
	tr  [64]byte
	s1  vector
	s2  vector
	t0  vector
	// Corresponding parameters.
	par *params
}
