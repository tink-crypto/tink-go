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

package rsassapss

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"math/big"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	internal "github.com/tink-crypto/tink-go/v2/internal/signature"
	"github.com/tink-crypto/tink-go/v2/keyset"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	rsassapsspb "github.com/tink-crypto/tink-go/v2/proto/rsa_ssa_pss_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	signerKeyVersion = 0
	signerTypeURL    = "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey"
)

type signerKeyManager struct{}

var _ registry.PrivateKeyManager = (*signerKeyManager)(nil)

func hashName(h commonpb.HashType) string { return commonpb.HashType_name[int32(h)] }

func (km *signerKeyManager) Primitive(serializedKey []byte) (any, error) {
	keySerialization, err := protoserialization.NewKeySerialization(&tinkpb.KeyData{
		TypeUrl:         signerTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, tinkpb.OutputPrefixType_RAW, 0)
	if err != nil {
		return nil, err
	}
	key, err := protoserialization.ParseKey(keySerialization)
	if err != nil {
		return nil, err
	}
	signerKey, ok := key.(*PrivateKey)
	if !ok {
		return nil, fmt.Errorf("rsassapss_signer_key_manager: invalid key type: got %T, want %T", key, (*PrivateKey)(nil))
	}
	return NewSigner(signerKey, internalapi.Token{})
}

func validateRSAPSSPrivateKey(privKey *rsassapsspb.RsaSsaPssPrivateKey) error {
	if err := keyset.ValidateKeyVersion(privKey.GetVersion(), signerKeyVersion); err != nil {
		return err
	}
	if err := validateRSAPSSPublicKey(privKey.GetPublicKey()); err != nil {
		return err
	}
	if len(privKey.GetD()) == 0 ||
		len(privKey.GetPublicKey().GetN()) == 0 ||
		len(privKey.GetPublicKey().GetE()) == 0 ||
		len(privKey.GetP()) == 0 ||
		len(privKey.GetQ()) == 0 ||
		len(privKey.GetDp()) == 0 ||
		len(privKey.GetDq()) == 0 ||
		len(privKey.GetCrt()) == 0 {
		return fmt.Errorf("rsassapss_signer_key_manager: invalid key")
	}
	return nil
}

func (km *signerKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := &rsassapsspb.RsaSsaPssPrivateKey{}
	if err := proto.Unmarshal(serializedPrivKey, privKey); err != nil {
		return nil, err
	}
	if err := validateRSAPSSPrivateKey(privKey); err != nil {
		return nil, err
	}
	serializedPubKey, err := proto.Marshal(privKey.GetPublicKey())
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         verifierTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

func (km *signerKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, fmt.Errorf("rsassapss_signer_key_manager: invalid key format")
	}
	keyFormat := &rsassapsspb.RsaSsaPssKeyFormat{}
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, err
	}
	params := keyFormat.GetParams()
	if params.GetSigHash() != params.GetMgf1Hash() {
		return nil, fmt.Errorf("rsassapss_signer_key_manager: rsassapss hash and mgf1 hash must be the same")
	}
	if params.GetSaltLength() < 0 {
		return nil, fmt.Errorf("rsassapss_signer_key_manager: salt length can't be negative")
	}
	if err := internal.ValidateRSAPublicKeyParams(params.GetSigHash(), int(keyFormat.GetModulusSizeInBits()), keyFormat.GetPublicExponent()); err != nil {
		return nil, err
	}
	privKey, err := rsa.GenerateKey(rand.Reader, int(keyFormat.GetModulusSizeInBits()))
	if err != nil {
		return nil, err
	}
	return &rsassapsspb.RsaSsaPssPrivateKey{
		Version: signerKeyVersion,
		PublicKey: &rsassapsspb.RsaSsaPssPublicKey{
			Version: signerKeyVersion,
			Params:  keyFormat.GetParams(),
			N:       privKey.PublicKey.N.Bytes(),
			E:       big.NewInt(int64(privKey.PublicKey.E)).Bytes(),
		},
		D:  privKey.D.Bytes(),
		P:  privKey.Primes[0].Bytes(),
		Q:  privKey.Primes[1].Bytes(),
		Dp: privKey.Precomputed.Dp.Bytes(),
		Dq: privKey.Precomputed.Dq.Bytes(),
		// In crypto/rsa `Qinv` is the "Chinese Remainder Theorem
		// coefficient q^(-1) mod p". This corresponds with `Crt` in
		// the Tink proto. This is unrelated to `CRTValues`, which
		// contains values specifically for additional primes, which
		// are not supported by Tink.
		Crt: privKey.Precomputed.Qinv.Bytes(),
	}, nil
}

func (km *signerKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         signerTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

func (km *signerKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == signerTypeURL
}

func (km *signerKeyManager) TypeURL() string {
	return signerTypeURL
}
