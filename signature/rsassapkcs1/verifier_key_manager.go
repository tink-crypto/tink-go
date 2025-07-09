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

package rsassapkcs1

import (
	"errors"
	"fmt"
	"math/big"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	internal "github.com/tink-crypto/tink-go/v2/internal/signature"
	"github.com/tink-crypto/tink-go/v2/keyset"
	rsassapkcs1pb "github.com/tink-crypto/tink-go/v2/proto/rsa_ssa_pkcs1_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	verifierKeyVersion = 0
	verifierTypeURL    = "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey"
)

var errUnimplemented = errors.New("rsassapkcs1_verifier_key_manager: not implemented")

type verifierKeyManager struct{}

var _ registry.KeyManager = (*verifierKeyManager)(nil)

func (km *verifierKeyManager) Primitive(serializedKey []byte) (any, error) {
	keySerialization, err := protoserialization.NewKeySerialization(&tinkpb.KeyData{
		TypeUrl:         verifierTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, tinkpb.OutputPrefixType_RAW, 0)
	if err != nil {
		return nil, err
	}
	key, err := protoserialization.ParseKey(keySerialization)
	if err != nil {
		return nil, err
	}
	verifierKey, ok := key.(*PublicKey)
	if !ok {
		return nil, fmt.Errorf("rsassapkcs1_verifier_key_manager: invalid key type: got %T, want %T", key, (*PublicKey)(nil))
	}
	return NewVerifier(verifierKey, internalapi.Token{})
}

func validatePublicKey(pubKey *rsassapkcs1pb.RsaSsaPkcs1PublicKey) error {
	if err := keyset.ValidateKeyVersion(pubKey.GetVersion(), verifierKeyVersion); err != nil {
		return err
	}
	hashAlg := hashName(pubKey.GetParams().GetHashType())
	return internal.ValidateRSAPublicKeyParams(hashAlg, new(big.Int).SetBytes(pubKey.GetN()).BitLen(), pubKey.GetE())
}

func (km *verifierKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errUnimplemented
}

func (km *verifierKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errUnimplemented
}

func (km *verifierKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == verifierTypeURL
}

func (km *verifierKeyManager) TypeURL() string {
	return verifierTypeURL
}
