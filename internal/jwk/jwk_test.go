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

	// Convert JWK Set to KeysetHandle
	handle, err := jwk.ToPublicKeysetHandle([]byte(jwkSet), jwk.Ed25519SupportTink)
	if err != nil {
		t.Fatalf("ToPublicKeysetHandle() err = %v, want nil", err)
	}

	// Convert KeysetHandle back to JWK Set
	gotJWKSet, err := jwk.FromPublicKeysetHandle(handle, jwk.Ed25519SupportTink)
	if err != nil {
		t.Fatalf("FromPublicKeysetHandle() err = %v, want nil", err)
	}

	// Compare the original and converted JWK Sets
	want := &spb.Struct{}
	if err := want.UnmarshalJSON([]byte(jwkSet)); err != nil {
		t.Fatalf("want.UnmarshalJSON() err = %v, want nil", err)
	}
	got := &spb.Struct{}
	if err := got.UnmarshalJSON(gotJWKSet); err != nil {
		t.Fatalf("got.UnmarshalJSON() err = %v, want nil", err)
	}

	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("mismatch in jwk sets: diff (-want +got):\n%s", diff)
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

	// Attempt to convert JWK Set to KeysetHandle with Ed25519SupportNone
	_, err := jwk.ToPublicKeysetHandle([]byte(jwkSet), jwk.Ed25519SupportNone)
	if err == nil {
		t.Fatalf("ToPublicKeysetHandle() err = nil, want error")
	}

	// Convert JWK Set to KeysetHandle
	handle, err := jwk.ToPublicKeysetHandle([]byte(jwkSet), jwk.Ed25519SupportTink)
	if err != nil {
		t.Fatalf("ToPublicKeysetHandle() err = %v, want nil", err)
	}

	// Attempt to convert KeysetHandle back to JWK Set with Ed25519SupportNone
	_, err = jwk.FromPublicKeysetHandle(handle, jwk.Ed25519SupportNone)
	if err == nil {
		t.Fatalf("FromPublicKeysetHandle() err = nil, want error")
	}
}
