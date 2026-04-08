// Copyright 2026 Google LLC
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

package compositemldsa_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	internal "github.com/tink-crypto/tink-go/v2/internal/signature/compositemldsa"
)

func TestCompositeMLDSALabel(t *testing.T) {
	for _, tc := range []struct {
		desc               string
		mlDSAInstance      internal.MLDSAInstance
		classicalAlgorithm internal.ClassicalAlgorithm
		expectedLabel      string
	}{
		{
			desc:               "MLDSA65-Ed25519",
			mlDSAInstance:      internal.MLDSA65,
			classicalAlgorithm: internal.Ed25519,
			expectedLabel:      "COMPSIG-MLDSA65-Ed25519-SHA512",
		},
		{
			desc:               "MLDSA65-ECDSAP256",
			mlDSAInstance:      internal.MLDSA65,
			classicalAlgorithm: internal.ECDSAP256,
			expectedLabel:      "COMPSIG-MLDSA65-ECDSA-P256-SHA512",
		},
		{
			desc:               "MLDSA65-RSA3072PSS",
			mlDSAInstance:      internal.MLDSA65,
			classicalAlgorithm: internal.RSA3072PSS,
			expectedLabel:      "COMPSIG-MLDSA65-RSA3072-PSS-SHA512",
		},
		{
			desc:               "MLDSA65-RSA3072PKCS1",
			mlDSAInstance:      internal.MLDSA65,
			classicalAlgorithm: internal.RSA3072PKCS1,
			expectedLabel:      "COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512",
		},
		{
			desc:               "MLDSA87-ECDSAP384",
			mlDSAInstance:      internal.MLDSA87,
			classicalAlgorithm: internal.ECDSAP384,
			expectedLabel:      "COMPSIG-MLDSA87-ECDSA-P384-SHA512",
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			label, err := internal.ComputeLabel(tc.mlDSAInstance, tc.classicalAlgorithm)
			if err != nil {
				t.Fatalf("CompositeMLDSALabel(%v, %v) err = %v, want nil", tc.mlDSAInstance, tc.classicalAlgorithm, err)
			}
			if label != tc.expectedLabel {
				t.Errorf("CompositeMLDSALabel(%v, %v) = %v, want %v", tc.mlDSAInstance, tc.classicalAlgorithm, label, tc.expectedLabel)
			}
		})
	}
}

func TestComputeCompositeMLDSAMessagePrime(t *testing.T) {
	// Test vector from C++ internal/composite_ml_dsa_util_boringssl_test.cc,
	// which is based on Draft 14 Appendix D.
	//
	// NOTE: The C++ test vector uses an empty context string (len(ctx) = 0).
	// The current Go implementation also inserts a single null byte (like
	// len(ctx)=0) as per the expected logic, so it produces the same message
	// prime as the C++ test vector.

	message, _ := hex.DecodeString("00010203040506070809")
	label := "COMPSIG-MLDSA65-ECDSA-P256-SHA512"

	// C++ expected value (with len(ctx)=0):
	// 436f6d706f73697465416c676f726974686d5369676e61747572657332303235 + // Prefix
	// 434f4d505349472d4d4c44534136352d45434453412d503235362d534841353132 + // Label
	// 00 + // len(ctx)=0
	// 0f89ee1fcb7b0a4f7809d1267a029719004c5a5e5ec323a7c3523a20974f9a3f202f56fadba4cd9e8d654ab9f2e96dc5c795ea176fa20ede8d854c342f903533 // hash

	// Go expected value:
	expectedGoHex := "436f6d706f73697465416c676f726974686d5369676e61747572657332303235" + // Prefix
		"434f4d505349472d4d4c44534136352d45434453412d503235362d534841353132" + // Label
		"00" + // null byte
		"0f89ee1fcb7b0a4f7809d1267a029719004c5a5e5ec323a7c3523a20974f9a3f202f56fadba4cd9e8d654ab9f2e96dc5c795ea176fa20ede8d854c342f903533" // hash

	expected, _ := hex.DecodeString(expectedGoHex)

	got := internal.ComputeMessagePrime(label, message)
	if !bytes.Equal(got, expected) {
		t.Errorf("ComputeCompositeMLDSAMessagePrime(%v, %v) = %x, want %x", label, message, got, expected)
	}
}
