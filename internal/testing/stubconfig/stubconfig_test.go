// Copyright 2024 Google LLC
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

package stubconfig_test

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/testing/stubconfig"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

type stubKeyManager struct{}

func (s stubKeyManager) Primitive(_ []byte) (any, error)              { panic("not needed in test") }
func (s stubKeyManager) NewKey(_ []byte) (proto.Message, error)       { panic("not needed in test") }
func (s stubKeyManager) DoesSupport(_ string) bool                    { panic("not needed in test") }
func (s stubKeyManager) TypeURL() string                              { panic("not needed in test") }
func (s stubKeyManager) NewKeyData(_ []byte) (*tinkpb.KeyData, error) { panic("not needed in test") }

func TestStubConfig(t *testing.T) {
	c := stubconfig.NewStubConfig()
	if c == nil {
		t.Fatalf("stubconfig.NewStubConfig() = nil, want not nil")
	}

	l := len(c.KeyManagers)
	if l != 0 {
		t.Fatalf("Initial number of registered key types = %d, want 0", l)
	}

	err := c.RegisterKeyManager("", stubKeyManager{}, internalapi.Token{})
	if err != nil {
		t.Fatalf("StubConfig.RegisterKeyManager(): err = %v, want nil", err)
	}

	l = len(c.KeyManagers)
	if l != 1 {
		t.Fatalf("Number of registered key types = %d, want 1", l)
	}
}
