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

// Package slhdsa implements SLH-DSA as specified in NIST FIPS 205 (https://doi.org/10.6028/NIST.FIPS.205).
package slhdsa

import "math/bits"

type params struct {
	// SLH-DSA parameters (see Table 2 of the SLH-DSA specification).
	n   uint32
	h   uint32
	d   uint32
	hp  uint32
	a   uint32
	k   uint32
	lgw uint32
	m   uint32

	// Derived parameters (defined by Algorithm 1 and Equations 5.1, 5.2, 5.3, and 5.4 of the SLH-DSA specification).
	w    uint32
	len1 uint32
	len2 uint32
	len  uint32

	// Hashing functions.
	pHMsg   func(r []byte, pkSeed []byte, pkRoot []byte, msg []byte, m uint32) []byte
	pPrf    func(pkSeed []byte, skSeed []byte, adrs *address, n uint32) []byte
	pPrfMsg func(skPrf []byte, optRand []byte, M []byte, n uint32) []byte
	pF      func(pkSeed []byte, adrs *address, M1 []byte, n uint32) []byte
	pH      func(pkSeed []byte, adrs *address, M2 []byte, n uint32) []byte
	pTl     func(pkSeed []byte, adrs *address, Ml []byte, n uint32) []byte
}

func (p *params) hHMsg(r []byte, pkSeed []byte, pkRoot []byte, msg []byte) []byte {
	return p.pHMsg(r, pkSeed, pkRoot, msg, p.m)
}

func (p *params) hPrf(pkSeed []byte, skSeed []byte, adrs *address) []byte {
	return p.pPrf(pkSeed, skSeed, adrs, p.n)
}

func (p *params) hPrfMsg(skPrf []byte, optRand []byte, msg []byte) []byte {
	return p.pPrfMsg(skPrf, optRand, msg, p.n)
}

func (p *params) hF(pkSeed []byte, adrs *address, msg1 []byte) []byte {
	return p.pF(pkSeed, adrs, msg1, p.n)
}

func (p *params) hH(pkSeed []byte, adrs *address, msg2 []byte) []byte {
	return p.pH(pkSeed, adrs, msg2, p.n)
}

func (p *params) hTl(pkSeed []byte, adrs *address, msgl []byte) []byte {
	return p.pTl(pkSeed, adrs, msgl, p.n)
}

type paramsOpts struct {
	n   uint32
	h   uint32
	d   uint32
	hp  uint32
	a   uint32
	k   uint32
	lgw uint32
	m   uint32
}

type hashParamsOpts struct {
	pHMsg   func(r []byte, pkSeed []byte, pkRoot []byte, msg []byte, m uint32) []byte
	pPrf    func(pkSeed []byte, skSeed []byte, adrs *address, n uint32) []byte
	pPrfMsg func(skPrf []byte, optRand []byte, M []byte, n uint32) []byte
	pF      func(pkSeed []byte, adrs *address, M1 []byte, n uint32) []byte
	pH      func(pkSeed []byte, adrs *address, M2 []byte, n uint32) []byte
	pTl     func(pkSeed []byte, adrs *address, Ml []byte, n uint32) []byte
}

func newParams(par paramsOpts, hashPar hashParamsOpts) *params {
	// These are defined by Algorithm 1 and Equations 5.1, 5.2, 5.3, and 5.4 of the SLH-DSA specification.
	w := uint32(1) << par.lgw
	len1 := (8*par.n + par.lgw - 1) / par.lgw
	log2 := func(x uint32) uint32 { return uint32(bits.Len(uint(x)) - 1) }
	len2 := log2(len1*(w-1))/par.lgw + 1
	len := len1 + len2
	return &params{
		par.n, par.h, par.d, par.hp, par.a, par.k, par.lgw, par.m,
		w, len1, len2, len,
		hashPar.pHMsg, hashPar.pPrf, hashPar.pPrfMsg, hashPar.pF, hashPar.pH, hashPar.pTl,
	}
}

// Parameters defined in Table 2 of the SLH-DSA specification.
var (
	param128s = paramsOpts{
		n:   16,
		h:   63,
		d:   7,
		hp:  9,
		a:   12,
		k:   14,
		lgw: 4,
		m:   30,
	}

	param128f = paramsOpts{
		n:   16,
		h:   66,
		d:   22,
		hp:  3,
		a:   6,
		k:   33,
		lgw: 4,
		m:   34,
	}

	param192s = paramsOpts{
		n:   24,
		h:   63,
		d:   7,
		hp:  9,
		a:   14,
		k:   17,
		lgw: 4,
		m:   39,
	}

	param192f = paramsOpts{
		n:   24,
		h:   66,
		d:   22,
		hp:  3,
		a:   8,
		k:   33,
		lgw: 4,
		m:   42,
	}

	param256s = paramsOpts{
		n:   32,
		h:   64,
		d:   8,
		hp:  8,
		a:   14,
		k:   22,
		lgw: 4,
		m:   47,
	}

	param256f = paramsOpts{
		n:   32,
		h:   68,
		d:   17,
		hp:  4,
		a:   9,
		k:   35,
		lgw: 4,
		m:   49,
	}

	hashParamShake = hashParamsOpts{
		pHMsg:   shakeHMsg,
		pPrf:    shakePrf,
		pPrfMsg: shakePrfMsg,
		pF:      shakeF,
		pH:      shakeH,
		pTl:     shakeTl,
	}

	hashParamSha2C1 = hashParamsOpts{
		pHMsg:   sha2C1HMsg,
		pPrf:    sha2C1Prf,
		pPrfMsg: sha2C1PrfMsg,
		pF:      sha2C1F,
		pH:      sha2C1H,
		pTl:     sha2C1Tl,
	}

	hashParamSha2C35 = hashParamsOpts{
		pHMsg:   sha2C35HMsg,
		pPrf:    sha2C35Prf,
		pPrfMsg: sha2C35PrfMsg,
		pF:      sha2C35F,
		pH:      sha2C35H,
		pTl:     sha2C35Tl,
	}
)

// Matching parameter set names as in Table 2 of the SLH-DSA specification.
var (
	// SLH_DSA_SHA2_128s defines parameters for SLH-DSA-SHA2-128s.
	SLH_DSA_SHA2_128s = newParams(param128s, hashParamSha2C1)
	// SLH_DSA_SHAKE_128s defines parameters for SLH-DSA-SHAKE-128s.
	SLH_DSA_SHAKE_128s = newParams(param128s, hashParamShake)
	// SLH_DSA_SHA2_128f defines parameters for SLH-DSA-SHA2-128f.
	SLH_DSA_SHA2_128f = newParams(param128f, hashParamSha2C1)
	// SLH_DSA_SHAKE_128f defines parameters for SLH-DSA-SHAKE-128f.
	SLH_DSA_SHAKE_128f = newParams(param128f, hashParamShake)
	// SLH_DSA_SHA2_192s defines parameters for SLH-DSA-SHA2-192s.
	SLH_DSA_SHA2_192s = newParams(param192s, hashParamSha2C35)
	// SLH_DSA_SHAKE_192s defines parameters for SLH-DSA-SHAKE-192s.
	SLH_DSA_SHAKE_192s = newParams(param192s, hashParamShake)
	// SLH_DSA_SHA2_192f defines parameters for SLH-DSA-SHA2-192f.
	SLH_DSA_SHA2_192f = newParams(param192f, hashParamSha2C35)
	// SLH_DSA_SHAKE_192f defines parameters for SLH-DSA-SHAKE-192f.
	SLH_DSA_SHAKE_192f = newParams(param192f, hashParamShake)
	// SLH_DSA_SHA2_256s defines parameters for SLH-DSA-SHA2-256s.
	SLH_DSA_SHA2_256s = newParams(param256s, hashParamSha2C35)
	// SLH_DSA_SHAKE_256s defines parameters for SLH-DSA-SHAKE-256s.
	SLH_DSA_SHAKE_256s = newParams(param256s, hashParamShake)
	// SLH_DSA_SHA2_256f defines parameters for SLH-DSA-SHA2-256f.
	SLH_DSA_SHA2_256f = newParams(param256f, hashParamSha2C35)
	// SLH_DSA_SHAKE_256f defines parameters for SLH-DSA-SHAKE-256f.
	SLH_DSA_SHAKE_256f = newParams(param256f, hashParamShake)
)
