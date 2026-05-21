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
		t.Fatal("ToPublicKeysetHandle() err = nil, want error for oversized public exponent")
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
		t.Fatalf("ToPublicKeysetHandle() err = %v, want nil for valid RS256 key", err)
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
