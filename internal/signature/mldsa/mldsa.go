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
