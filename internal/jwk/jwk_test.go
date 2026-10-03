// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jwk_test

import (
	"encoding/base64"
	"fmt"
	"slices"
	"testing"

	spb "google.golang.org/protobuf/types/known/structpb"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/internal/jwk"
)

func TestEd25519KeyConversion(t *testing.T) {
	jwkSet := `{
		"keys":[
			{
				"kty":"OKP",
				"crv":"Ed25519",
				"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPmd1Xo",
				"use":"sig",
				"alg":"EdDSA",
				"key_ops":["verify"]
			}
		]
	}`

	// Convert JWK Set to KeysetHandle.
	handle, err := jwk.ToPublicKeysetHandle([]byte(jwkSet), jwk.Ed25519SupportTink)
	if err != nil {
		t.Fatalf("ToPublicKeysetHandle() err = %v, want nil", err)
	}

	// Convert KeysetHandle back to JWK Set.
	gotJWKSet, err := jwk.FromPublicKeysetHandle(handle, jwk.Ed25519SupportTink)
	if err != nil {
		t.Fatalf("FromPublicKeysetHandle() err = %v, want nil", err)
	}

	// Compare the original and converted JWK Sets.
	want := &spb.Struct{}
	if err := want.UnmarshalJSON([]byte(jwkSet)); err != nil {
		t.Fatalf("want.UnmarshalJSON() err = %v, want nil", err)
	}
	got := &spb.Struct{}
	if err := got.UnmarshalJSON(gotJWKSet); err != nil {
		t.Fatalf("got.UnmarshalJSON() err = %v, want nil", err)
	}

	if got.GetFields()["keys"].GetListValue().GetValues()[0].GetStructValue().GetFields()["kid"].GetStringValue() == "" {
		t.Errorf("kid is empty, expected a randomly generated value")
	}

	// Remove the random generated kid from the got JWK Set to compare with the original JWK Set.
	delete(got.GetFields()["keys"].GetListValue().GetValues()[0].GetStructValue().GetFields(), "kid")

	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("mismatch in jwk sets: diff (-want +got):\n%s", diff)
	}
}

// n2048Base64 is a base64url-encoded 2048-bit RSA modulus used in tests.
// Taken from:
// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/rsa_pkcs1_2048_test.json#L13
const n2048Base64 = "s1EKK81M5kTFtZSuUFnhKy8FS2WNXaWVmi_fGHG4CLw98-Yo0nkuUarVwSS0O9pFPcpc3kvPKOe9Tv-6DLS3Qru21aATy2PRqjqJ4CYn71OYtSwM_ZfSCKvrjXybzgu-sBmobdtYm-sppbdL-GEHXGd8gdQw8DDCZSR6-dPJFAzLZTCdB-Ctwe_RXPF-ewVdfaOGjkZIzDoYDw7n-OHnsYCYozkbTOcWHpjVevipR-IBpGPi1rvKgFnlcG6d_tj0hWRl_6cS7RqhjoiNEtxqoJzpXs_Kg8xbCxXbCchkf11STA8udiCjQWuWI8rcDwl69XMmHJjIQAqhKvOOQ8rYTQ"

// TestRS256OversizedPublicExponentRejected verifies that a JWK with a
// public exponent that cannot be represented as int64 is rejected when
// importing an RS256 (PKCS1) key. This mirrors the existing check in the
// PSS (PS256/PS384/PS512) import path and prevents silent truncation of
// a malformed exponent via big.Int.Int64().
//
// The crafted exponent is 2^64 + 65537 (base64url: AQAAAAAAAQAB). Its
// big.Int.Int64() value happens to equal 65537 (low-64-bit wrap-around),
// so without the IsInt64 guard the import would silently succeed with the
// truncated value instead of returning an error.
func TestRS256OversizedPublicExponentRejected(t *testing.T) {
	// "e" encodes 2^64 + 65537 (9 bytes: 0x010000000000010001).
	// IsInt64() returns false; Int64() silently wraps to 65537.
	jwkSet := `{
		"keys":[
			{
				"kty":"RSA",
				"alg":"RS256",
				"n":"` + n2048Base64 + `",
				"e":"AQAAAAAAAQAB",
				"use":"sig",
				"key_ops":["verify"]
			}
		]
	}`

	_, err := jwk.ToPublicKeysetHandle([]byte(jwkSet), jwk.Ed25519SupportNone)
	if err == nil {
		t.Errorf("ToPublicKeysetHandle() err = nil, want error for oversized public exponent")
	}
}

// TestRS256NormalPublicExponentAccepted verifies that a well-formed RS256 JWK
// with the standard exponent 65537 (base64url: AQAB) is imported successfully.
func TestRS256NormalPublicExponentAccepted(t *testing.T) {
	jwkSet := `{
		"keys":[
			{
				"kty":"RSA",
				"alg":"RS256",
				"n":"` + n2048Base64 + `",
				"e":"AQAB",
				"use":"sig",
				"key_ops":["verify"]
			}
		]
	}`

	_, err := jwk.ToPublicKeysetHandle([]byte(jwkSet), jwk.Ed25519SupportNone)
	if err != nil {
		t.Errorf("ToPublicKeysetHandle() err = %v, want nil for valid RS256 key", err)
	}
}

func TestEd25519KeyConversionNotSupported(t *testing.T) {
	jwkSet := `{
		"keys":[
			{
				"kty":"OKP",
				"crv":"Ed25519",
				"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPmd1Xo",
				"use":"sig",
				"alg":"EdDSA",
				"key_ops":["verify"]
			}
		]
	}`

	// Attempt to convert JWK Set to KeysetHandle with Ed25519SupportNone.
	_, err := jwk.ToPublicKeysetHandle([]byte(jwkSet), jwk.Ed25519SupportNone)
	if err == nil {
		t.Fatalf("ToPublicKeysetHandle() err = nil, want error")
	}

	// Convert JWK Set to KeysetHandle.
	handle, err := jwk.ToPublicKeysetHandle([]byte(jwkSet), jwk.Ed25519SupportTink)
	if err != nil {
		t.Fatalf("ToPublicKeysetHandle() err = %v, want nil", err)
	}

	// Attempt to convert KeysetHandle back to JWK Set with Ed25519SupportNone.
	_, err = jwk.FromPublicKeysetHandle(handle, jwk.Ed25519SupportNone)
	if err == nil {
		t.Fatalf("FromPublicKeysetHandle() err = nil, want error")
	}
}

// TestNonCanonicalBase64Rejected verifies that a JWK containing a base64url-encoded
// field with non-zero unused trailing bits is rejected per RFC 4648 §3.5.
func TestNonCanonicalBase64Rejected(t *testing.T) {
	// Canonical Ed25519 "x" ends in 'o' (unused bits are 0).
	validJWKSet := `{
		"keys":[
			{
				"kty":"OKP",
				"crv":"Ed25519",
				"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPmd1Xo",
				"use":"sig",
				"alg":"EdDSA",
				"key_ops":["verify"]
			}
		]
	}`
	if _, err := jwk.ToPublicKeysetHandle([]byte(validJWKSet), jwk.Ed25519SupportTink); err != nil {
		t.Fatalf("ToPublicKeysetHandle() err = %v, want nil for valid key", err)
	}

	// Non-canonical "x" ends in 'p' (unused bits are non-zero).
	invalidJWKSet := `{
		"keys":[
			{
				"kty":"OKP",
				"crv":"Ed25519",
				"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPmd1Xp",
				"use":"sig",
				"alg":"EdDSA",
				"key_ops":["verify"]
			}
		]
	}`
	if _, err := jwk.ToPublicKeysetHandle([]byte(invalidJWKSet), jwk.Ed25519SupportTink); err == nil {
		t.Errorf("ToPublicKeysetHandle() err = nil, want error for non-canonical base64 encoding")
	}
}

// TestESPublicKeyNonCanonicalCoordinateLengthsRejected verifies that ECDSA JWK
// imports enforce per-coordinate byte length checks (RFC 7518 §§6.2.1.2-6.2.1.3)
// rather than only checking the concatenated x||y buffer length in crypto/ecdh.
func TestESPublicKeyNonCanonicalCoordinateLengthsRejected(t *testing.T) {
	b64Enc := base64.URLEncoding.WithPadding(base64.NoPadding)
	mustDecode := func(t *testing.T, s string) []byte {
		t.Helper()
		b, err := b64Enc.DecodeString(s)
		if err != nil {
			t.Fatalf("DecodeString(%q) err = %v", s, err)
		}
		return b
	}

	curves := []struct {
		alg     string
		crv     string
		coordSz int
		validX  string
		validY  string
	}{
		{
			alg:     "ES256",
			crv:     "P-256",
			coordSz: 32,
			validX:  "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
			validY:  "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
		},
		{
			alg:     "ES384",
			crv:     "P-384",
			coordSz: 48,
			validX:  "AEUCTkKhRDEgJ2pTiyPoSsIOERywrB2xjBDgUH8LLg0Ao9xT2SxKadxLdRFIr8Ll",
			validY:  "wQcqkI9pV66PJFmJVyZ7BsqvFaqoWT-jAFvYNjsgdvAIpyB3MHWXkxNhlPYcpEIf",
		},
		{
			alg:     "ES512",
			crv:     "P-521",
			coordSz: 66,
			validX:  "AKRFrHHoTaFAO-d4sCOw78KyUlZijBgqfp2rXtkLZ_QQGLtDM2nScAilkryvw3c_4fM39CEygtSunFLI9xyUyE3m",
			validY:  "ANZK5JjTcNAKtezmXFvDSkrxdxPiuX2uPq6oR3M0pb2wqnfDL-nWeWcKb2nAOxYSyydsrZ98bxBL60lEr20x1Gc_",
		},
	}

	makeJWKSet := func(alg, crv, x, y string) []byte {
		return []byte(fmt.Sprintf(`{
			"keys":[
				{
					"kty":"EC",
					"crv":%q,
					"alg":%q,
					"x":%q,
					"y":%q,
					"use":"sig",
					"key_ops":["verify"]
				}
			]
		}`, crv, alg, x, y))
	}

	for _, c := range curves {
		t.Run(c.alg, func(t *testing.T) {
			rawX := mustDecode(t, c.validX)
			rawY := mustDecode(t, c.validY)
			if len(rawX) != c.coordSz || len(rawY) != c.coordSz {
				t.Fatalf("unexpected test vector sizes: len(x)=%d, len(y)=%d, want %d", len(rawX), len(rawY), c.coordSz)
			}

			// Baseline: canonical coordinate lengths must be accepted.
			if _, err := jwk.ToPublicKeysetHandle(makeJWKSet(c.alg, c.crv, c.validX, c.validY), jwk.Ed25519SupportNone); err != nil {
				t.Fatalf("ToPublicKeysetHandle() err = %v, want nil for canonical %s key", err, c.alg)
			}

			// Shifted splits of the valid point bytes (len(x) + len(y) == 2*coordSz, but len(x) != coordSz).
			xy := slices.Concat(rawX, rawY)
			for _, split := range []int{0, 1, c.coordSz - 1, c.coordSz + 1, 2*c.coordSz - 1, 2 * c.coordSz} {
				badX := b64Enc.EncodeToString(xy[:split])
				badY := b64Enc.EncodeToString(xy[split:])
				if _, err := jwk.ToPublicKeysetHandle(makeJWKSet(c.alg, c.crv, badX, badY), jwk.Ed25519SupportNone); err == nil {
					t.Errorf("ToPublicKeysetHandle() with split (%d, %d) err = nil, want error", split, 2*c.coordSz-split)
				}
			}

			// Extra leading zero byte on x or y.
			paddedX := b64Enc.EncodeToString(slices.Concat([]byte{0x00}, rawX))
			if _, err := jwk.ToPublicKeysetHandle(makeJWKSet(c.alg, c.crv, paddedX, c.validY), jwk.Ed25519SupportNone); err == nil {
				t.Errorf("ToPublicKeysetHandle() with oversized x err = nil, want error")
			}
			paddedY := b64Enc.EncodeToString(slices.Concat([]byte{0x00}, rawY))
			if _, err := jwk.ToPublicKeysetHandle(makeJWKSet(c.alg, c.crv, c.validX, paddedY), jwk.Ed25519SupportNone); err == nil {
				t.Errorf("ToPublicKeysetHandle() with oversized y err = nil, want error")
			}
		})
	}
}

// TestToPublicKeysetHandle_KeyCountLimit verifies that ToPublicKeysetHandle
// rejects JWK sets that exceed the maximum allowed key count.
//
// Without this limit, a caller processing an attacker-controlled JWK set
// (e.g. from a remote JWKS endpoint) would perform unbounded cryptographic
// allocations proportional to the number of keys in the set.
func TestToPublicKeysetHandle_KeyCountLimit(t *testing.T) {
	// Single valid RS256 key — repeated to build large sets.
	const singleKey = `{"kty":"RSA","alg":"RS256","use":"sig","n":"` + n2048Base64 + `","e":"AQAB"}`

	t.Run("exactly_1000_keys_accepted", func(t *testing.T) {
		keys := make([]string, 1000)
		for i := range keys {
			keys[i] = singleKey
		}
		jwkSet := `{"keys":[` + joinStrings(keys) + `]}`
		if _, err := jwk.ToPublicKeysetHandle([]byte(jwkSet), jwk.Ed25519SupportNone); err != nil {
			t.Errorf("ToPublicKeysetHandle() with 1000 keys err = %v, want nil", err)
		}
	})

	t.Run("1001_keys_rejected", func(t *testing.T) {
		keys := make([]string, 1001)
		for i := range keys {
			keys[i] = singleKey
		}
		jwkSet := `{"keys":[` + joinStrings(keys) + `]}`
		if _, err := jwk.ToPublicKeysetHandle([]byte(jwkSet), jwk.Ed25519SupportNone); err == nil {
			t.Error("ToPublicKeysetHandle() with 1001 keys err = nil, want error")
		}
	})
}

// joinStrings joins a slice of strings with commas.
func joinStrings(ss []string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += ","
		}
		result += s
	}
	return result
}
