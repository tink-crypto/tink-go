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
	"crypto/rand"
	"encoding/hex"
	"slices"
	"testing"
)

// TODO: b/433932274 - Add Wycheproof style tests.

func mustHexDecode(t *testing.T, hexString string) []byte {
	t.Helper()
	output, err := hex.DecodeString(hexString)
	if err != nil {
		t.Fatal(err)
	}
	return output
}

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

func TestPublicKeyLength(t *testing.T) {
	for _, tc := range []struct {
		name string
		par  *params
		want int
	}{
		{"SLH-DSA-SHA2-128s", SLH_DSA_SHA2_128s, 32},
		{"SLH-DSA-SHAKE-128s", SLH_DSA_SHAKE_128s, 32},
		{"SLH-DSA-SHA2-128f", SLH_DSA_SHA2_128f, 32},
		{"SLH-DSA-SHAKE-128f", SLH_DSA_SHAKE_128f, 32},
		{"SLH-DSA-SHA2-192s", SLH_DSA_SHA2_192s, 48},
		{"SLH-DSA-SHAKE-192s", SLH_DSA_SHAKE_192s, 48},
		{"SLH-DSA-SHA2-192f", SLH_DSA_SHA2_192f, 48},
		{"SLH-DSA-SHAKE-192f", SLH_DSA_SHAKE_192f, 48},
		{"SLH-DSA-SHA2-256s", SLH_DSA_SHA2_256s, 64},
		{"SLH-DSA-SHAKE-256s", SLH_DSA_SHAKE_256s, 64},
		{"SLH-DSA-SHA2-256f", SLH_DSA_SHA2_256f, 64},
		{"SLH-DSA-SHAKE-256f", SLH_DSA_SHAKE_256f, 64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.par.PublicKeyLength() != tc.want {
				t.Errorf("PublicKeyLength() = %v, want %v", tc.par.PublicKeyLength(), tc.want)
			}
		})
	}
}

func TestSecretKeyLength(t *testing.T) {
	for _, tc := range []struct {
		name string
		par  *params
		want int
	}{
		{"SLH-DSA-SHA2-128s", SLH_DSA_SHA2_128s, 64},
		{"SLH-DSA-SHAKE-128s", SLH_DSA_SHAKE_128s, 64},
		{"SLH-DSA-SHA2-128f", SLH_DSA_SHA2_128f, 64},
		{"SLH-DSA-SHAKE-128f", SLH_DSA_SHAKE_128f, 64},
		{"SLH-DSA-SHA2-192s", SLH_DSA_SHA2_192s, 96},
		{"SLH-DSA-SHAKE-192s", SLH_DSA_SHAKE_192s, 96},
		{"SLH-DSA-SHA2-192f", SLH_DSA_SHA2_192f, 96},
		{"SLH-DSA-SHAKE-192f", SLH_DSA_SHAKE_192f, 96},
		{"SLH-DSA-SHA2-256s", SLH_DSA_SHA2_256s, 128},
		{"SLH-DSA-SHAKE-256s", SLH_DSA_SHAKE_256s, 128},
		{"SLH-DSA-SHA2-256f", SLH_DSA_SHA2_256f, 128},
		{"SLH-DSA-SHAKE-256f", SLH_DSA_SHAKE_256f, 128},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.par.SecretKeyLength() != tc.want {
				t.Errorf("SecretKeyLength() = %v, want %v", tc.par.SecretKeyLength(), tc.want)
			}
		})
	}
}

func TestEncodeDecodePublicKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		par  *params
	}{
		{"SLH-DSA-SHA2-128s", SLH_DSA_SHA2_128s},
		{"SLH-DSA-SHAKE-128s", SLH_DSA_SHAKE_128s},
		{"SLH-DSA-SHA2-128f", SLH_DSA_SHA2_128f},
		{"SLH-DSA-SHAKE-128f", SLH_DSA_SHAKE_128f},
		{"SLH-DSA-SHA2-192s", SLH_DSA_SHA2_192s},
		{"SLH-DSA-SHAKE-192s", SLH_DSA_SHAKE_192s},
		{"SLH-DSA-SHA2-192f", SLH_DSA_SHA2_192f},
		{"SLH-DSA-SHAKE-192f", SLH_DSA_SHAKE_192f},
		{"SLH-DSA-SHA2-256s", SLH_DSA_SHA2_256s},
		{"SLH-DSA-SHAKE-256s", SLH_DSA_SHAKE_256s},
		{"SLH-DSA-SHA2-256f", SLH_DSA_SHA2_256f},
		{"SLH-DSA-SHAKE-256f", SLH_DSA_SHAKE_256f},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, pk := tc.par.KeyGen()
			pkEnc := pk.Encode()
			pkDec, err := tc.par.DecodePublicKey(pkEnc)
			if err != nil {
				t.Errorf("DecodePublicKey() err = %v, want nil", err)
			}
			if !slices.Equal(pk.pkSeed, pkDec.pkSeed) {
				t.Errorf("DecodePublicKey().pkSeed = %v, want %v", pkDec.pkSeed, pk.pkSeed)
			}
			if !slices.Equal(pk.pkRoot, pkDec.pkRoot) {
				t.Errorf("DecodePublicKey().pkRoot = %v, want %v", pkDec.pkRoot, pk.pkRoot)
			}
		})
	}
}

func TestEncodeDecodeSecretKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		par  *params
	}{
		{"SLH-DSA-SHA2-128s", SLH_DSA_SHA2_128s},
		{"SLH-DSA-SHAKE-128s", SLH_DSA_SHAKE_128s},
		{"SLH-DSA-SHA2-128f", SLH_DSA_SHA2_128f},
		{"SLH-DSA-SHAKE-128f", SLH_DSA_SHAKE_128f},
		{"SLH-DSA-SHA2-192s", SLH_DSA_SHA2_192s},
		{"SLH-DSA-SHAKE-192s", SLH_DSA_SHAKE_192s},
		{"SLH-DSA-SHA2-192f", SLH_DSA_SHA2_192f},
		{"SLH-DSA-SHAKE-192f", SLH_DSA_SHAKE_192f},
		{"SLH-DSA-SHA2-256s", SLH_DSA_SHA2_256s},
		{"SLH-DSA-SHAKE-256s", SLH_DSA_SHAKE_256s},
		{"SLH-DSA-SHA2-256f", SLH_DSA_SHA2_256f},
		{"SLH-DSA-SHAKE-256f", SLH_DSA_SHAKE_256f},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sk, _ := tc.par.KeyGen()
			skEnc := sk.Encode()
			skDec, err := tc.par.DecodeSecretKey(skEnc)
			if err != nil {
				t.Errorf("DecodeSecretKey() err = %v, want nil", err)
			}
			if !slices.Equal(sk.skSeed, skDec.skSeed) {
				t.Errorf("DecodeSecretKey().skSeed = %v, want %v", skDec.skSeed, sk.skSeed)
			}
			if !slices.Equal(sk.skPrf, skDec.skPrf) {
				t.Errorf("DecodeSecretKey().skPrf = %v, want %v", skDec.skPrf, sk.skPrf)
			}
			if !slices.Equal(sk.pkSeed, skDec.pkSeed) {
				t.Errorf("DecodeSecretKey().pkSeed = %v, want %v", skDec.pkSeed, sk.pkSeed)
			}
			if !slices.Equal(sk.pkRoot, skDec.pkRoot) {
				t.Errorf("DecodeSecretKey().pkRoot = %v, want %v", skDec.pkRoot, sk.pkRoot)
			}
		})
	}
}

func TestPublicKeyFromSecretKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		par  *params
	}{
		{"SLH-DSA-SHA2-128s", SLH_DSA_SHA2_128s},
		{"SLH-DSA_SHAKE-128s", SLH_DSA_SHAKE_128s},
		{"SLH-DSA-SHA2-128f", SLH_DSA_SHA2_128f},
		{"SLH-DSA-SHAKE-128f", SLH_DSA_SHAKE_128f},
		{"SLH-DSA-SHA2-192s", SLH_DSA_SHA2_192s},
		{"SLH-DSA-SHAKE-192s", SLH_DSA_SHAKE_192s},
		{"SLH-DSA-SHA2-192f", SLH_DSA_SHA2_192f},
		{"SLH-DSA-SHAKE-192f", SLH_DSA_SHAKE_192f},
		{"SLH-DSA-SHA2-256s", SLH_DSA_SHA2_256s},
		{"SLH-DSA-SHAKE-256s", SLH_DSA_SHAKE_256s},
		{"SLH-DSA-SHA2-256f", SLH_DSA_SHA2_256f},
		{"SLH-DSA-SHAKE-256f", SLH_DSA_SHAKE_256f},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sk, pk := tc.par.KeyGen()
			pkFromSk := sk.PublicKey()
			if !slices.Equal(pkFromSk.pkSeed, pk.pkSeed) {
				t.Errorf("pkFromSk.pkSeed = %v, want %v", pkFromSk.pkSeed, pk.pkSeed)
			}
			if !slices.Equal(pkFromSk.pkRoot, pk.pkRoot) {
				t.Errorf("pkFromSk.pkRoot = %v, want %v", pkFromSk.pkRoot, pk.pkRoot)
			}
		})
	}
}

func TestSignDeterministicVerifyKat(t *testing.T) {
	for _, tc := range katTestVectors(t) {
		t.Run(tc.name, func(t *testing.T) {
			skBytes := mustHexDecode(t, tc.sk)
			pkBytes := mustHexDecode(t, tc.pk)
			msgBytes := mustHexDecode(t, tc.msg)
			ctxBytes := mustHexDecode(t, tc.ctx)
			wantSigBytes := mustHexDecode(t, tc.wantSig)
			sk, err := tc.par.DecodeSecretKey(skBytes)
			if err != nil {
				t.Fatalf("par.DecodeSecretKey() err = %v, want nil", err)
			}
			pk, err := tc.par.DecodePublicKey(pkBytes)
			if err != nil {
				t.Fatalf("pk.DecodePublicKey() err = %v, want nil", err)
			}
			sig, err := sk.SignDeterministic(msgBytes, ctxBytes)
			if err != nil {
				t.Fatalf("sk.SignDeterministic() err = %v, want nil", err)
			}
			if !slices.Equal(sig, wantSigBytes) {
				t.Fatalf("sk.SignDeterministic() = %x, want %x", sig, wantSigBytes)
			}
			if err := pk.Verify(msgBytes, wantSigBytes, ctxBytes); err != nil {
				t.Errorf("pk.Verify() err = %v, want nil", err)
			}
		})
	}
}

func TestSignVerify(t *testing.T) {
	for _, tc := range []struct {
		name string
		par  *params
	}{
		{"SLH-DSA-SHA2-128s", SLH_DSA_SHA2_128s},
		{"SLH-DSA-SHAKE-128s", SLH_DSA_SHAKE_128s},
		{"SLH-DSA-SHA2-128f", SLH_DSA_SHA2_128f},
		{"SLH-DSA-SHAKE-128f", SLH_DSA_SHAKE_128f},
		{"SLH-DSA-SHA2-192s", SLH_DSA_SHA2_192s},
		{"SLH-DSA-SHAKE-192s", SLH_DSA_SHAKE_192s},
		{"SLH-DSA-SHA2-192f", SLH_DSA_SHA2_192f},
		{"SLH-DSA-SHAKE-192f", SLH_DSA_SHAKE_192f},
		{"SLH-DSA-SHA2-256s", SLH_DSA_SHA2_256s},
		{"SLH-DSA-SHAKE-256s", SLH_DSA_SHAKE_256s},
		{"SLH-DSA-SHA2-256f", SLH_DSA_SHA2_256f},
		{"SLH-DSA-SHAKE-256f", SLH_DSA_SHAKE_256f},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sk, pk := tc.par.KeyGen()
			var m [32]byte
			rand.Read(m[:])
			var ctx [32]byte
			rand.Read(ctx[:])
			signature, err := sk.Sign(m[:], ctx[:])
			if err != nil {
				t.Fatalf("sk.Sign() err = %v, want nil", err)
			}
			signature2, err := sk.Sign(m[:], ctx[:])
			if err != nil {
				t.Fatalf("sk.Sign() err = %v, want nil", err)
			}
			if slices.Equal(signature, signature2) {
				t.Fatal("sk.Sign() == sk.Sign(), want sk.Sign() != sk.Sign()")
			}
			if err := pk.Verify(m[:], signature, ctx[:]); err != nil {
				t.Fatalf("pk.Verify() err = %v, want nil", err)
			}
			signature[0] ^= 1 // Corrupt the signature.
			if err := pk.Verify(m[:], signature, ctx[:]); err == nil {
				t.Errorf("pk.Verify() = nil, want err")
			}
		})
	}
}

func TestSignDeterministicVerify(t *testing.T) {
	for _, tc := range []struct {
		name string
		par  *params
	}{
		{"SLH-DSA-SHA2-128s", SLH_DSA_SHA2_128s},
		{"SLH-DSA-SHAKE-128s", SLH_DSA_SHAKE_128s},
		{"SLH-DSA-SHA2-128f", SLH_DSA_SHA2_128f},
		{"SLH-DSA-SHAKE-128f", SLH_DSA_SHAKE_128f},
		{"SLH-DSA-SHA2-192s", SLH_DSA_SHA2_192s},
		{"SLH-DSA-SHAKE-192s", SLH_DSA_SHAKE_192s},
		{"SLH-DSA-SHA2-192f", SLH_DSA_SHA2_192f},
		{"SLH-DSA-SHAKE-192f", SLH_DSA_SHAKE_192f},
		{"SLH-DSA-SHA2-256s", SLH_DSA_SHA2_256s},
		{"SLH-DSA-SHAKE-256s", SLH_DSA_SHAKE_256s},
		{"SLH-DSA-SHA2-256f", SLH_DSA_SHA2_256f},
		{"SLH-DSA-SHAKE-256f", SLH_DSA_SHAKE_256f},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sk, pk := tc.par.KeyGen()
			var m [32]byte
			rand.Read(m[:])
			var ctx [32]byte
			rand.Read(ctx[:])
			signature, err := sk.SignDeterministic(m[:], ctx[:])
			if err != nil {
				t.Fatalf("sk.Sign() err = %v, want nil", err)
			}
			signature2, err := sk.SignDeterministic(m[:], ctx[:])
			if err != nil {
				t.Fatalf("sk.Sign() err = %v, want nil", err)
			}
			if !slices.Equal(signature, signature2) {
				t.Fatal("sk.SignDeterministic() != sk.SignDeterministic(), want sk.SignDeterministic() == sk.SignDeterministic()")
			}
			if err := pk.Verify(m[:], signature, ctx[:]); err != nil {
				t.Fatalf("pk.Verify() err = %v, want nil", err)
			}
			signature[0] ^= 1 // Corrupt the signature.
			if err := pk.Verify(m[:], signature, ctx[:]); err == nil {
				t.Errorf("pk.Verify() = nil, want err")
			}
		})
	}
}

func TestVerifyInvalidSignatureLength(t *testing.T) {
	for _, tc := range []struct {
		name string
		par  *params
	}{
		{"SLH-DSA-SHA2-128s", SLH_DSA_SHA2_128s},
		{"SLH-DSA-SHAKE-128s", SLH_DSA_SHAKE_128s},
		{"SLH-DSA-SHA2-128f", SLH_DSA_SHA2_128f},
		{"SLH-DSA-SHAKE-128f", SLH_DSA_SHAKE_128f},
		{"SLH-DSA-SHA2-192s", SLH_DSA_SHA2_192s},
		{"SLH-DSA-SHAKE-192s", SLH_DSA_SHAKE_192s},
		{"SLH-DSA-SHA2-192f", SLH_DSA_SHA2_192f},
		{"SLH-DSA-SHAKE-192f", SLH_DSA_SHAKE_192f},
		{"SLH-DSA-SHA2-256s", SLH_DSA_SHA2_256s},
		{"SLH-DSA-SHAKE-256s", SLH_DSA_SHAKE_256s},
		{"SLH-DSA-SHA2-256f", SLH_DSA_SHA2_256f},
		{"SLH-DSA-SHAKE-256f", SLH_DSA_SHAKE_256f},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, pk := tc.par.KeyGen()
			sigLenPlus1 := make([]byte, (1+pk.p.k*(1+pk.p.a)+pk.p.h+pk.p.d*pk.p.len)*pk.p.n+1)
			if err := pk.Verify([]byte{}, sigLenPlus1, []byte{}); err == nil {
				t.Errorf("pk.Verify() = nil, want err")
			}
			sigLenMinus1 := make([]byte, (1+pk.p.k*(1+pk.p.a)+pk.p.h+pk.p.d*pk.p.len)*pk.p.n-1)
			if err := pk.Verify([]byte{}, sigLenMinus1, []byte{}); err == nil {
				t.Errorf("pk.Verify() = nil, want err")
			}
		})
	}
}

func TestDecodePublicKeyInvalidLength(t *testing.T) {
	for _, tc := range []struct {
		name string
		par  *params
	}{
		{"SLH-DSA-SHA2-128s", SLH_DSA_SHA2_128s},
		{"SLH-DSA-SHAKE-128s", SLH_DSA_SHAKE_128s},
		{"SLH-DSA-SHA2-128f", SLH_DSA_SHA2_128f},
		{"SLH-DSA-SHAKE-128f", SLH_DSA_SHAKE_128f},
		{"SLH-DSA-SHA2-192s", SLH_DSA_SHA2_192s},
		{"SLH-DSA-SHAKE-192s", SLH_DSA_SHAKE_192s},
		{"SLH-DSA-SHA2-192f", SLH_DSA_SHA2_192f},
		{"SLH-DSA-SHAKE-192f", SLH_DSA_SHAKE_192f},
		{"SLH-DSA-SHA2-256s", SLH_DSA_SHA2_256s},
		{"SLH-DSA-SHAKE-256s", SLH_DSA_SHAKE_256s},
		{"SLH-DSA-SHA2-256f", SLH_DSA_SHA2_256f},
		{"SLH-DSA-SHAKE-256f", SLH_DSA_SHAKE_256f},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkEncPlus1 := make([]byte, 2*tc.par.n+1)
			if _, err := tc.par.DecodePublicKey(pkEncPlus1); err == nil {
				t.Errorf("DecodePublicKey() = nil, want err")
			}
			pkEncMinus1 := make([]byte, 2*tc.par.n-1)
			if _, err := tc.par.DecodePublicKey(pkEncMinus1); err == nil {
				t.Errorf("DecodePublicKey() = nil, want err")
			}
		})
	}
}

func TestDecodeSecretKeyInvalidLength(t *testing.T) {
	for _, tc := range []struct {
		name string
		par  *params
	}{
		{"SLH-DSA-SHA2-128s", SLH_DSA_SHA2_128s},
		{"SLH-DSA-SHAKE-128s", SLH_DSA_SHAKE_128s},
		{"SLH-DSA-SHA2-128f", SLH_DSA_SHA2_128f},
		{"SLH-DSA-SHAKE-128f", SLH_DSA_SHAKE_128f},
		{"SLH-DSA-SHA2-192s", SLH_DSA_SHA2_192s},
		{"SLH-DSA-SHAKE-192s", SLH_DSA_SHAKE_192s},
		{"SLH-DSA-SHA2-192f", SLH_DSA_SHA2_192f},
		{"SLH-DSA-SHAKE-192f", SLH_DSA_SHAKE_192f},
		{"SLH-DSA-SHA2-256s", SLH_DSA_SHA2_256s},
		{"SLH-DSA-SHAKE-256s", SLH_DSA_SHAKE_256s},
		{"SLH-DSA-SHA2-256f", SLH_DSA_SHA2_256f},
		{"SLH-DSA-SHAKE-256f", SLH_DSA_SHAKE_256f},
	} {
		t.Run(tc.name, func(t *testing.T) {
			skEncPlus1 := make([]byte, 4*tc.par.n+1)
			if _, err := tc.par.DecodeSecretKey(skEncPlus1); err == nil {
				t.Errorf("DecodeSecretKey() = nil, want err")
			}
			skEncMinus1 := make([]byte, 4*tc.par.n-1)
			if _, err := tc.par.DecodeSecretKey(skEncMinus1); err == nil {
				t.Errorf("DecodeSecretKey() = nil, want err")
			}
		})
	}
}

func TestSignVerifyContextInvalidLength(t *testing.T) {
	sk, pk := SLH_DSA_SHA2_128s.KeyGen()
	var m [32]byte
	rand.Read(m[:])
	var ctx [256]byte
	rand.Read(ctx[:])
	_, err := sk.Sign(m[:], ctx[:])
	if err == nil {
		t.Errorf("sk.Sign(...) = nil, want err")
	}
	signature, err := sk.Sign(m[:], ctx[:255])
	if err != nil {
		t.Errorf("sk.Sign(...) = err, want nil")
	}
	err = pk.Verify(m[:], signature, ctx[:])
	if err == nil {
		t.Errorf("pk.Verify(...) = nil, want err")
	}
}

func TestSignDeterministicContextTooLong(t *testing.T) {
	sk, _ := SLH_DSA_SHA2_128s.KeyGen()
	var m [32]byte
	rand.Read(m[:])
	var ctx [256]byte
	rand.Read(ctx[:])
	_, err := sk.SignDeterministic(m[:], ctx[:])
	if err == nil {
		t.Fatalf("sk.SignDeterministic(...) = nil, want err")
	}
}
