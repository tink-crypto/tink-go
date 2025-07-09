// Copyright 2023 Google LLC
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

package keyderivation_test

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/prf"
	prfderpb "github.com/tink-crypto/tink-go/v2/proto/prf_based_deriver_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestDeriveKeyset_CreateKeysetFailsWithInconsistentOutputPrefixTypes(t *testing.T) {
	keyFormat := &prfderpb.PrfBasedDeriverKeyFormat{
		PrfKeyTemplate: prf.HKDFSHA256PRFKeyTemplate(),
		Params: &prfderpb.PrfBasedDeriverParams{
			DerivedKeyTemplate: aead.AES256GCMNoPrefixKeyTemplate(),
		},
	}
	serializedFormat, err := proto.Marshal(keyFormat)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	template := &tinkpb.KeyTemplate{
		TypeUrl:          "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
		OutputPrefixType: tinkpb.OutputPrefixType_TINK,
		Value:            serializedFormat,
	}
	if _, err := keyset.NewHandle(template); err == nil {
		t.Errorf("keyset.NewHandle() err = nil, want non-nil")
	}
}
