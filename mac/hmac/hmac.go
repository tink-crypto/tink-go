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

// Package hmac provides the key manager for HMAC.
package hmac

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/keygenregistry"
	"github.com/tink-crypto/tink-go/v2/internal/legacykeymanager"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/internal/registryconfig"
	hmpb "github.com/tink-crypto/tink-go/v2/proto/hmac_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func init() {
	if err := protoserialization.RegisterKeyParser(typeURL, new(keyParser)); err != nil {
		panic(fmt.Sprintf("hmac.init() failed: %v", err))
	}
	if err := protoserialization.RegisterKeySerializer[*Key](new(keySerializer)); err != nil {
		panic(fmt.Sprintf("hmac.init() failed: %v", err))
	}
	if err := protoserialization.RegisterParametersSerializer[*Parameters](new(parametersSerializer)); err != nil {
		panic(fmt.Sprintf("hmac.init() failed: %v", err))
	}
	if err := protoserialization.RegisterParametersParser(typeURL, new(parametersParser)); err != nil {
		panic(fmt.Sprintf("hmac.init() failed: %v", err))
	}
	if err := registryconfig.RegisterPrimitiveConstructor[*Key](primitiveConstructor); err != nil {
		panic(fmt.Sprintf("hmac.init() failed: %v", err))
	}
	if err := keygenregistry.RegisterKeyCreator[*Parameters](createKey); err != nil {
		panic(fmt.Sprintf("hmac.init() failed: %v", err))
	}

	if err := registry.RegisterKeyManager(legacykeymanager.New(typeURL, &registryconfig.RegistryConfig{}, tinkpb.KeyData_SYMMETRIC, func(b []byte) (proto.Message, error) {
		protoKey := &hmpb.HmacKey{}
		if err := proto.Unmarshal(b, protoKey); err != nil {
			return nil, err
		}
		return protoKey, nil
	})); err != nil {
		panic(fmt.Sprintf("hmac.init() failed: %v", err))
	}
}
