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

package daeadconfig_test

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/daead/aessiv"
	"github.com/tink-crypto/tink-go/v2/internal/config/daeadconfig"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testutil/testonlyinsecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func mustMarshal(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", m, err)
	}
	return b
}

func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) err = %v, want nil", s, err)
	}
	return b
}

const (
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/aes_siv_cmac_test.json#L2865.
	aesSIVKeyHex        = "c25cafc6018b98dfbb79a40ec89c575a4f88c4116489bba27707479800c0130235334a45dbe8d8dae3da8dcb45bbe5dce031b0f68ded544fda7eca30d6749442"
	aesSIVMsgHex        = "beec61030fa3d670337196beade6aeaa"
	aesSIVAad           = "deeb0ccf3aef47a296ed1ca8f4ae5907"
	aesSIVCiphertextHex = "5865208eab9163db85cab9f96d846234a2626aae22f5c17c9aad4b501f4416e4"
)

func TestConfigV0MACFailsIfKeyNotMAC(t *testing.T) {
	configV0 := daeadconfig.V0()
	aesGCMParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantNoPrefix,
		IVSizeInBytes:  12,
	})
	if err != nil {
		t.Fatalf("aessiv.NewParameters() err = %v, want nil", err)
	}
	aesGCMKey, err := aesgcm.NewKey(secretdata.NewBytesFromData(mustHexDecode(t, "ea3b016bdd387dd64d837c71683808f335dbdc53598a4ea8c5f952473fafaf5f"), testonlyinsecuresecretdataaccess.Token()), 0, aesGCMParams)
	if err != nil {
		t.Fatalf(" aessiv.NewKey() err = %v, want nil", err)
	}
	if _, err := configV0.PrimitiveFromKey(aesGCMKey, internalapi.Token{}); err == nil {
		t.Errorf("configV0.PrimitiveFromKeyData() err = nil, want error")
	}
}

func TestConfigV0MAC(t *testing.T) {
	configV0 := daeadconfig.V0()

	// AES-SIV.
	aesSIVParams, err := aessiv.NewParameters(64, aessiv.VariantNoPrefix)
	if err != nil {
		t.Fatalf("aessiv.NewParameters() err = %v, want nil", err)
	}
	aesSIVKey, err := aessiv.NewKey(secretdata.NewBytesFromData(mustHexDecode(t, aesSIVKeyHex), testonlyinsecuresecretdataaccess.Token()), 0, aesSIVParams)
	if err != nil {
		t.Fatalf(" aessiv.NewKey() err = %v, want nil", err)
	}

	for _, test := range []struct {
		name       string
		key        key.Key
		msg        []byte
		aad        []byte
		ciphertext []byte
	}{
		{
			name:       "AES-SIV",
			key:        aesSIVKey,
			msg:        mustHexDecode(t, aesSIVMsgHex),
			aad:        mustHexDecode(t, aesSIVAad),
			ciphertext: mustHexDecode(t, aesSIVCiphertextHex),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ps, err := protoserialization.SerializeKey(test.key)
			if err != nil {
				t.Fatalf("protoserialization.SerializeKey() err = %v, want nil", err)
			}
			if _, err := configV0.PrimitiveFromKeyData(ps.KeyData(), internalapi.Token{}); err == nil {
				t.Fatalf("configV0.PrimitiveFromKeyData() err = nil, want error")
			}

			d, err := configV0.PrimitiveFromKey(test.key, internalapi.Token{})
			if err != nil {
				t.Fatalf("configV0.PrimitiveFromKey() err = %v, want nil", err)
			}
			m, ok := d.(tink.DeterministicAEAD)
			if !ok {
				t.Fatalf("d was of type %v, want tink.MAC", reflect.TypeOf(d))
			}
			got, err := m.DecryptDeterministically(test.ciphertext, test.aad)
			if err != nil {
				t.Fatalf("d.DecryptDeterministically() err = %v, want nil", err)
			}
			if !bytes.Equal(got, test.msg) {
				t.Errorf("d.DecryptDeterministically() = %v, want %v", got, test.msg)
			}
		})
	}
}
