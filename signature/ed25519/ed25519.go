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

// Package ed25519 provides ED25519 keys and parameters definitions, and key
// managers.
package ed25519

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/keygenregistry"
	"github.com/tink-crypto/tink-go/v2/internal/legacykeymanager"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveregistry"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/internal/registryconfig"
	ed25519pb "github.com/tink-crypto/tink-go/v2/proto/ed25519_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func init() {
	if err := registry.RegisterKeyManager(legacykeymanager.NewPrivateKeyManager(signerTypeURL, &registryconfig.RegistryConfig{}, tinkpb.KeyData_ASYMMETRIC_PRIVATE, func(b []byte) (proto.Message, error) {
		protoKey := &ed25519pb.Ed25519PrivateKey{}
		if err := proto.Unmarshal(b, protoKey); err != nil {
			return nil, err
		}
		return protoKey, nil
	})); err != nil {
		panic(fmt.Sprintf("ecdsa.init() failed: %v", err))
	}
	if err := registry.RegisterKeyManager(legacykeymanager.New(verifierTypeURL, &registryconfig.RegistryConfig{}, tinkpb.KeyData_ASYMMETRIC_PUBLIC, func(b []byte) (proto.Message, error) {
		protoKey := &ed25519pb.Ed25519PublicKey{}
		if err := proto.Unmarshal(b, protoKey); err != nil {
			return nil, err
		}
		return protoKey, nil
	})); err != nil {
		panic(fmt.Sprintf("ecdsa.init() failed: %v", err))
	}
	if err := protoserialization.RegisterKeySerializer[*PublicKey](&publicKeySerializer{}); err != nil {
		panic(fmt.Sprintf("ed25519.init() failed: %v", err))
	}
	if err := protoserialization.RegisterKeyParser(verifierTypeURL, &publicKeyParser{}); err != nil {
		panic(fmt.Sprintf("ed25519.init() failed: %v", err))
	}
	if err := protoserialization.RegisterKeySerializer[*PrivateKey](&privateKeySerializer{}); err != nil {
		panic(fmt.Sprintf("ed25519.init() failed: %v", err))
	}
	if err := protoserialization.RegisterKeyParser(signerTypeURL, &privateKeyParser{}); err != nil {
		panic(fmt.Sprintf("ed25519.init() failed: %v", err))
	}
	if err := protoserialization.RegisterParametersSerializer[*Parameters](&parametersSerializer{}); err != nil {
		panic(fmt.Sprintf("ed25519.init() failed: %v", err))
	}
	if err := protoserialization.RegisterParametersParser(signerTypeURL, &parametersParser{}); err != nil {
		panic(fmt.Sprintf("ed25519.init() failed: %v", err))
	}
	if err := primitiveregistry.RegisterPrimitiveConstructor[*PublicKey](verifierConstructor); err != nil {
		panic(fmt.Sprintf("ed25519.init() failed: %v", err))
	}
	if err := primitiveregistry.RegisterPrimitiveConstructor[*PrivateKey](signerConstructor); err != nil {
		panic(fmt.Sprintf("ed25519.init() failed: %v", err))
	}
	if err := keygenregistry.RegisterKeyCreator[*Parameters](createPrivateKey); err != nil {
		panic(fmt.Sprintf("ed25519.init() failed: %v", err))
	}
}
