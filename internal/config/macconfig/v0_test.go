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

package macconfig_test

import (
	"encoding/hex"
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/config/macconfig"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/mac/aescmac"
	"github.com/tink-crypto/tink-go/v2/mac/hmac"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/tink"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func mustMarshal(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err=%v, want nil", m, err)
	}
	return b
}

func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) err=%v, want nil", s, err)
	}
	return b
}

const (
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/hmac_sha256_test.json#L37.
	hmacKeyHex = "85a7cbaae825bb82c9b6f6c5c2af5ac03d1f6daa63d2a93c189948ec41b9ded9"
	hmacMsgHex = "a59b"
	hmacTagHex = "0fe2f13bba2198f6dda1a084be928e304e9cb16a56bc0b7b939a073280244373"
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/aes_cmac_test.json#L1869
	aesCMACKeyHex = "ea3b016bdd387dd64d837c71683808f335dbdc53598a4ea8c5f952473fafaf5f"
	aesCMACMsgHex = "6601"
	aesCMACTagHex = "c7c44e31c466334992d6f9de3c771634"
)

func TestConfigV0MAC(t *testing.T) {
	configV0 := macconfig.V0()

	// HMAC.
	hmacParams, err := hmac.NewParameters(hmac.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 32,
		HashType:       hmac.SHA256,
		Variant:        hmac.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("hmac.NewParameters() err=%v, want nil", err)
	}
	hmacKey, err := hmac.NewKey(secretdata.NewBytesFromData(mustHexDecode(t, hmacKeyHex), insecuresecretdataaccess.Token{}), hmacParams, 0)
	if err != nil {
		t.Fatalf(" hmac.NewKey() err=%v, want nil", err)
	}
	hmacKeyPS, err := protoserialization.SerializeKey(hmacKey)
	if err != nil {
		t.Fatalf("protoserialization.SerializeKey() err=%v, want nil", err)
	}

	// AES-CMAC.
	aesCMACParams, err := aescmac.NewParameters(aescmac.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		Variant:        aescmac.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aescmac.NewParameters() err=%v, want nil", err)
	}
	aesCMACKey, err := aescmac.NewKey(secretdata.NewBytesFromData(mustHexDecode(t, "ea3b016bdd387dd64d837c71683808f335dbdc53598a4ea8c5f952473fafaf5f"), insecuresecretdataaccess.Token{}), aesCMACParams, 0)
	if err != nil {
		t.Fatalf(" aescmac.NewKey() err=%v, want nil", err)
	}
	aesCMACKeyPS, err := protoserialization.SerializeKey(aesCMACKey)
	if err != nil {
		t.Fatalf("protoserialization.SerializeKey() err=%v, want nil", err)
	}

	for _, test := range []struct {
		name    string
		key     key.Key
		keyData *tinkpb.KeyData
		msg     []byte
		tag     []byte
	}{
		{
			name:    "HMAC",
			key:     hmacKey,
			keyData: hmacKeyPS.KeyData(),
			msg:     mustHexDecode(t, hmacMsgHex),
			tag:     mustHexDecode(t, hmacTagHex),
		},
		{
			name:    "AES-CMAC",
			key:     aesCMACKey,
			keyData: aesCMACKeyPS.KeyData(),
			msg:     mustHexDecode(t, aesCMACMsgHex),
			tag:     mustHexDecode(t, aesCMACTagHex),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			// No key manager for this key type.
			if _, err := configV0.PrimitiveFromKeyData(test.keyData, internalapi.Token{}); err == nil {
				t.Fatalf("configV0.PrimitiveFromKeyData() err=nil, want error")
			}

			mac, err := configV0.PrimitiveFromKey(test.key, internalapi.Token{})
			if err != nil {
				t.Fatalf("configV0.PrimitiveFromKey() err=%v, want nil", err)
			}
			m, ok := mac.(tink.MAC)
			if !ok {
				t.Fatalf("mac was of type %v, want tink.MAC", reflect.TypeOf(mac))
			}
			if err := m.VerifyMAC(test.tag, test.msg); err != nil {
				t.Errorf("mac.VerifyMAC() err=%v, want nil", err)
			}
		})
	}
}
