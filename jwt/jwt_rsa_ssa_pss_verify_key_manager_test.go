// Copyright 2022 Google LLC
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

package jwt

import (
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	jrsppb "github.com/tink-crypto/tink-go/v2/proto/jwt_rsa_ssa_pss_go_proto"
)

const testJWTPSVerifierKeyType = "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey"

func makeValidPSPublicKey() (*jrsppb.JwtRsaSsaPssPublicKey, error) {
	// Public key taken from: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2
	n, err := base64Decode(
		"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx" +
			"HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs" +
			"D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH" +
			"SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV" +
			"MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8" +
			"NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ")
	if err != nil {
		return nil, fmt.Errorf("base64 decoding modulus: %v", err)
	}
	e, err := base64Decode("AQAB")
	if err != nil {
		return nil, fmt.Errorf("base64 decoding public exponent: %v", err)
	}
	return &jrsppb.JwtRsaSsaPssPublicKey{
		Algorithm: jrsppb.JwtRsaSsaPssAlgorithm_PS256,
		Version:   0,
		N:         n,
		E:         e,
		CustomKid: nil,
	}, nil
}

func TestJWTPSVerifierNotImplemented(t *testing.T) {
	km, err := registry.GetKeyManager(testJWTPSVerifierKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTPSVerifierKeyType, err)
	}
	keyFormat := &jrsppb.JwtRsaSsaPssKeyFormat{
		Version:           0,
		Algorithm:         jrsppb.JwtRsaSsaPssAlgorithm_PS256,
		ModulusSizeInBits: 3072,
		PublicExponent:    []byte{0x01, 0x00, 0x01}, // 65537 aka F4
	}
	serializedKeyFormat, err := proto.Marshal(keyFormat)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	if _, err := km.NewKey(serializedKeyFormat); err == nil {
		t.Fatalf("km.NewKey() err = nil, want error")
	}
	if _, err := km.NewKeyData(serializedKeyFormat); err == nil {
		t.Fatalf("km.NewKeyData() err = nil, want error")
	}
}

func TestJWTPSVerifierDoesSupport(t *testing.T) {
	km, err := registry.GetKeyManager(testJWTPSVerifierKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTPSVerifierKeyType, err)
	}
	if !km.DoesSupport(testJWTPSVerifierKeyType) {
		t.Errorf("DoesSupport(%q) = false, want true", testJWTPSVerifierKeyType)
	}
	if km.DoesSupport("not.the.actual.key.type") {
		t.Errorf("km.DoesSupport('not.the.actual.key.type') = true, want false")
	}
}

func TestJWTPSVerifierTypeURL(t *testing.T) {
	km, err := registry.GetKeyManager(testJWTPSVerifierKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTPSVerifierKeyType, err)
	}
	if km.TypeURL() != testJWTPSVerifierKeyType {
		t.Errorf("km.TypeURL() = %q, want %q", km.TypeURL(), testJWTPSVerifierKeyType)
	}
}

func TestJWTPSVerifierPrimitiveAlwaysFails(t *testing.T) {
	km, err := registry.GetKeyManager(testJWTPSVerifierKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTPSVerifierKeyType, err)
	}
	pubKey, err := makeValidPSPublicKey()
	if err != nil {
		t.Fatalf("makeValidPSPublicKey() err = %v, want nil", err)
	}
	serializedPubKey, err := proto.Marshal(pubKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	if _, err := km.Primitive(serializedPubKey); err == nil {
		t.Errorf("km.Primitive() err = %v, want nil", err)
	}
}
