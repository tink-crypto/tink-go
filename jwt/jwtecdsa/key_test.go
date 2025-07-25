// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/Lycense-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

package jwtecdsa_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtecdsa"
)

const (
	// Taken from https://datatracker.ietf.org/doc/html/rfc6979.html#appendix-A.2.5
	p256PublicKeyPointXHex       = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
	p256PublicKeyPointYHex       = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"
	p256PublicKeyPointHex        = "04" + p256PublicKeyPointXHex + p256PublicKeyPointYHex
	p256PublicKeyPointInvalidHex = "04" +
		"60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6" +
		"08c8049879c6278b227334847415851500000000000000000000000000000000"

	// From
	// https://github.com/C2SP/wycheproof/blob/4109e5ed72e2a49ad39186fc75284261dd4ca5cd/testvectors/ecdsa_secp256r1_sha256_p1363_test.json#L27C27-L27C157
	otherP256PublicKeyPointHex = "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e"

	// Taken from https://datatracker.ietf.org/doc/html/rfc6979.html#appendix-A.2.6
	p384PublicKeyPointXHex       = "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13"
	p384PublicKeyPointYHex       = "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720"
	p384PublicKeyPointHex        = "04" + p384PublicKeyPointXHex + p384PublicKeyPointYHex
	p384PublicKeyPointInvalidHex = "04" +
		"EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13" +
		"8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DF00000000000000000000000000000000000000000000000000"

	// Taken from https://datatracker.ietf.org/doc/html/rfc6979.html#appendix-A.2.7
	p521PublicKeyPointXHex       = "01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4"
	p521PublicKeyPointYHex       = "00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5"
	p521PublicKeyPointHex        = "04" + p521PublicKeyPointXHex + p521PublicKeyPointYHex
	p521PublicKeyPointInvalidHex = "04" +
		"01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4" +
		"00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A000000000000000000000000000000000000000000000000000"
)

func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) err = %v, want nil", s, err)
	}
	return decoded
}

func TestNewPublicKey(t *testing.T) {
	for _, algorithmAndPointHex := range []struct {
		alg      jwtecdsa.Algorithm
		pointHex string
	}{
		{alg: jwtecdsa.ES256, pointHex: p256PublicKeyPointHex},
		{alg: jwtecdsa.ES384, pointHex: p384PublicKeyPointHex},
		{alg: jwtecdsa.ES512, pointHex: p521PublicKeyPointHex},
	} {
		for _, tc := range []struct {
			name       string
			opts       jwtecdsa.PublicKeyOpts
			wantKID    string
			wantHasKID bool
		}{
			{
				name: algorithmAndPointHex.alg.String() + "_Base64EncodedKeyIDAsKID",
				opts: jwtecdsa.PublicKeyOpts{
					PublicPoint:   mustHexDecode(t, algorithmAndPointHex.pointHex),
					IDRequirement: 0x1ac6a944,
					HasCustomKID:  false,
					CustomKID:     "",
					Parameters:    mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, algorithmAndPointHex.alg),
				},
				wantKID:    "GsapRA",
				wantHasKID: true,
			},
			{
				name: algorithmAndPointHex.alg.String() + "_CustomKID",
				opts: jwtecdsa.PublicKeyOpts{
					PublicPoint:   mustHexDecode(t, algorithmAndPointHex.pointHex),
					IDRequirement: 0,
					HasCustomKID:  true,
					CustomKID:     "customKid777",
					Parameters:    mustCreateParameters(t, jwtecdsa.CustomKID, algorithmAndPointHex.alg),
				},
				wantKID:    "customKid777",
				wantHasKID: true,
			},
			{
				name: algorithmAndPointHex.alg.String() + "_IgnoredKID",
				opts: jwtecdsa.PublicKeyOpts{
					PublicPoint:   mustHexDecode(t, algorithmAndPointHex.pointHex),
					IDRequirement: 0,
					HasCustomKID:  false,
					CustomKID:     "",
					Parameters:    mustCreateParameters(t, jwtecdsa.IgnoredKID, algorithmAndPointHex.alg),
				},
				wantKID:    "",
				wantHasKID: false,
			},
		} {
			t.Run(fmt.Sprintf("%v_%v", tc.opts.Parameters.Algorithm(), tc.opts.Parameters.KIDStrategy()), func(t *testing.T) {
				got, err := jwtecdsa.NewPublicKey(tc.opts)
				if err != nil {
					t.Fatalf("jwtecdsa.NewPublicKey() err = %v, want nil", err)
				}
				kid, hasKID := got.KID()
				if kid != tc.wantKID || hasKID != tc.wantHasKID {
					t.Errorf("got.KID() = %q, %v, want %q, %v", kid, hasKID, tc.wantKID, tc.wantHasKID)
				}
				idRequirement, hasIDRequirement := got.IDRequirement()
				if idRequirement != tc.opts.IDRequirement || hasIDRequirement != tc.opts.Parameters.HasIDRequirement() {
					t.Errorf("got.IDRequirement() = %q, %v, want %q, %v", kid, hasKID, tc.wantKID, tc.wantHasKID)
				}

				got2, err := jwtecdsa.NewPublicKey(tc.opts)
				if err != nil {
					t.Fatalf("jwtecdsa.NewPublicKey() err = %v, want nil", err)
				}
				if diff := cmp.Diff(got, got2); diff != "" {
					t.Errorf("unexpected diff (-want +got):\n%s", diff)
				}
			})
		}
	}
}

func TestPublicKeyEqual_Different(t *testing.T) {
	for _, tc := range []struct {
		name         string
		opts1, opts2 jwtecdsa.PublicKeyOpts
	}{
		{
			name: "Base64EncodedKeyIDAsKID_DifferentIDRequirement",
			opts1: jwtecdsa.PublicKeyOpts{
				PublicPoint:   mustHexDecode(t, p256PublicKeyPointHex),
				IDRequirement: 0x01020304,
				HasCustomKID:  false,
				CustomKID:     "",
				Parameters:    mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES256),
			},
			opts2: jwtecdsa.PublicKeyOpts{
				PublicPoint:   mustHexDecode(t, p256PublicKeyPointHex),
				IDRequirement: 0x01020305,
				HasCustomKID:  false,
				CustomKID:     "",
				Parameters:    mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES256),
			},
		},
		{
			name: "Base64EncodedKeyIDAsKID_DifferentAlgorithm",
			opts1: jwtecdsa.PublicKeyOpts{
				PublicPoint:   mustHexDecode(t, p256PublicKeyPointHex),
				IDRequirement: 0x01020304,
				HasCustomKID:  false,
				CustomKID:     "",
				Parameters:    mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES256),
			},
			opts2: jwtecdsa.PublicKeyOpts{
				PublicPoint:   mustHexDecode(t, p384PublicKeyPointHex),
				IDRequirement: 0x01020304,
				HasCustomKID:  false,
				CustomKID:     "",
				Parameters:    mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES384),
			},
		},
		{
			name: "Base64EncodedKeyIDAsKID_DifferentPublicPoint",
			opts1: jwtecdsa.PublicKeyOpts{
				PublicPoint:   mustHexDecode(t, p256PublicKeyPointHex),
				IDRequirement: 0x01020304,
				HasCustomKID:  false,
				CustomKID:     "",
				Parameters:    mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES256),
			},
			opts2: jwtecdsa.PublicKeyOpts{
				PublicPoint:   mustHexDecode(t, otherP256PublicKeyPointHex),
				IDRequirement: 0x01020304,
				HasCustomKID:  false,
				CustomKID:     "",
				Parameters:    mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES256),
			},
		},
		{
			name: "CustomKID_DifferentCustomKID",
			opts1: jwtecdsa.PublicKeyOpts{
				PublicPoint:   mustHexDecode(t, p256PublicKeyPointHex),
				IDRequirement: 0,
				HasCustomKID:  true,
				CustomKID:     "AABBCC",
				Parameters:    mustCreateParameters(t, jwtecdsa.CustomKID, jwtecdsa.ES256),
			},
			opts2: jwtecdsa.PublicKeyOpts{
				PublicPoint:   mustHexDecode(t, p256PublicKeyPointHex),
				IDRequirement: 0,
				HasCustomKID:  true,
				CustomKID:     "DDEEFF",
				Parameters:    mustCreateParameters(t, jwtecdsa.CustomKID, jwtecdsa.ES256),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key1, err := jwtecdsa.NewPublicKey(tc.opts1)
			if err != nil {
				t.Fatalf("jwtecdsa.NewPublicKey() err = %v, want nil", err)
			}
			key2, err := jwtecdsa.NewPublicKey(tc.opts2)
			if err != nil {
				t.Fatalf("jwtecdsa.NewPublicKey() err = %v, want nil", err)
			}
			if key1.Equal(key2) {
				t.Errorf("(%v).Equal(%v) = true, want false", key1, key2)
			}
		})
	}
}

func TestNewPublicKey_Errors(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts jwtecdsa.PublicKeyOpts
	}{
		{
			name: "ES256_Base64EncodedKeyIDAsKID_custom_kid_set",
			opts: jwtecdsa.PublicKeyOpts{
				PublicPoint:   mustHexDecode(t, p256PublicKeyPointHex),
				IDRequirement: 0x01020304,
				HasCustomKID:  true,
				CustomKID:     "",
				Parameters:    mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES256),
			},
		},
		{
			name: "ES256_CustomKID_id_requirement_and_custom_kid",
			opts: jwtecdsa.PublicKeyOpts{
				PublicPoint:   mustHexDecode(t, p256PublicKeyPointHex),
				IDRequirement: 0x01020304,
				HasCustomKID:  true,
				CustomKID:     "AABBCC",
				Parameters:    mustCreateParameters(t, jwtecdsa.CustomKID, jwtecdsa.ES256),
			},
		},
		{
			name: "ES256_CustomKID_has_custom_kid_false",
			opts: jwtecdsa.PublicKeyOpts{
				PublicPoint:   mustHexDecode(t, p256PublicKeyPointHex),
				IDRequirement: 0,
				HasCustomKID:  false,
				CustomKID:     "",
				Parameters:    mustCreateParameters(t, jwtecdsa.CustomKID, jwtecdsa.ES256),
			},
		},
		{
			name: "ES256_IgnoredKID_custom_kid_not_empty",
			opts: jwtecdsa.PublicKeyOpts{
				PublicPoint:   mustHexDecode(t, p256PublicKeyPointHex),
				IDRequirement: 0,
				HasCustomKID:  false,
				CustomKID:     "AABBCC",
				Parameters:    mustCreateParameters(t, jwtecdsa.IgnoredKID, jwtecdsa.ES256),
			},
		},
		{
			name: "ES256_IgnoredKID_id_requirement_set",
			opts: jwtecdsa.PublicKeyOpts{
				PublicPoint:   mustHexDecode(t, p256PublicKeyPointHex),
				IDRequirement: 0x01020304,
				HasCustomKID:  false,
				CustomKID:     "",
				Parameters:    mustCreateParameters(t, jwtecdsa.IgnoredKID, jwtecdsa.ES256),
			},
		},
		{
			name: "ES256_IgnoredKID_custom_kid_set",
			opts: jwtecdsa.PublicKeyOpts{
				PublicPoint:   mustHexDecode(t, p256PublicKeyPointHex),
				IDRequirement: 0,
				HasCustomKID:  true,
				CustomKID:     "AABBCC",
				Parameters:    mustCreateParameters(t, jwtecdsa.IgnoredKID, jwtecdsa.ES256),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := jwtecdsa.NewPublicKey(tc.opts); err == nil {
				t.Errorf("jwtecdsa.NewPublicKey() err = nil, want error")
			} else {
				t.Logf("jwtecdsa.NewPublicKey() err = %v", err)
			}
		})
	}

	// Invalid point tests.
	for _, tc := range []struct {
		name string
		opts jwtecdsa.PublicKeyOpts
	}{
		{
			name: "mismatched_curve",
			opts: jwtecdsa.PublicKeyOpts{
				PublicPoint:   mustHexDecode(t, p384PublicKeyPointInvalidHex),
				IDRequirement: 0x01020304,
				HasCustomKID:  false,
				CustomKID:     "",
				Parameters:    mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES256),
			},
		},
		{
			name: "ES256_invalid_point",
			opts: jwtecdsa.PublicKeyOpts{
				PublicPoint:   mustHexDecode(t, p256PublicKeyPointInvalidHex),
				IDRequirement: 0x01020304,
				HasCustomKID:  false,
				CustomKID:     "",
				Parameters:    mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES256),
			},
		},
		{
			name: "ES384_invalid_point",
			opts: jwtecdsa.PublicKeyOpts{
				PublicPoint:   mustHexDecode(t, p384PublicKeyPointInvalidHex),
				IDRequirement: 0x01020304,
				HasCustomKID:  false,
				CustomKID:     "",
				Parameters:    mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES384),
			},
		},
		{
			name: "ES512_invalid_point",
			opts: jwtecdsa.PublicKeyOpts{
				PublicPoint:   mustHexDecode(t, p521PublicKeyPointInvalidHex),
				IDRequirement: 0x01020304,
				HasCustomKID:  false,
				CustomKID:     "",
				Parameters:    mustCreateParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES512),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := jwtecdsa.NewPublicKey(tc.opts); err == nil {
				t.Errorf("jwtecdsa.NewPublicKey() err = nil, want error")
			} else {
				t.Logf("jwtecdsa.NewPublicKey() err = %v", err)
			}
		})
	}

}
