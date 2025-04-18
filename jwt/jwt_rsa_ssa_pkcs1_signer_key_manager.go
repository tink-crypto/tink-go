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
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapkcs1"
	jrsppb "github.com/tink-crypto/tink-go/v2/proto/jwt_rsa_ssa_pkcs1_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	jwtRSSignerKeyVersion = 0
	jwtRSSignerTypeURL    = "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey"
)

var (
	errRSInvalidPrivateKey = errors.New("invalid JwtRsaSsaPkcs1PrivateKey")
	errRSInvalidKeyFormat  = errors.New("invalid RSA SSA PKCS1 key format")
)

// jwtRSSignerKeyManager implements the KeyManager interface
// for JWT Signing using the 'RS256', 'RS384', and 'RS512' JWA algorithm.
type jwtRSSignerKeyManager struct{}

var _ registry.PrivateKeyManager = (*jwtRSSignerKeyManager)(nil)

func bytesToBigInt(v []byte) *big.Int {
	return new(big.Int).SetBytes(v)
}

func protoAlgToHashType(algo jrsppb.JwtRsaSsaPkcs1Algorithm) (rsassapkcs1.HashType, error) {
	switch algo {
	case jrsppb.JwtRsaSsaPkcs1Algorithm_RS256:
		return rsassapkcs1.SHA256, nil
	case jrsppb.JwtRsaSsaPkcs1Algorithm_RS384:
		return rsassapkcs1.SHA384, nil
	case jrsppb.JwtRsaSsaPkcs1Algorithm_RS512:
		return rsassapkcs1.SHA512, nil
	default:
		return 0, fmt.Errorf("invalid algorithm: %v", algo)
	}
}

func (km *jwtRSSignerKeyManager) Primitive(serializedKey []byte) (any, error) {
	if serializedKey == nil {
		return nil, fmt.Errorf("invalid JwtRsaSsaPkcs1PrivateKey")
	}
	privKey := &jrsppb.JwtRsaSsaPkcs1PrivateKey{}
	if err := proto.Unmarshal(serializedKey, privKey); err != nil {
		return nil, fmt.Errorf("failed to unmarshal RsaSsaPkcs1PrivateKey: %v", err)
	}
	if err := validateRSPrivateKey(privKey); err != nil {
		return nil, err
	}

	n := bytesToBigInt(privKey.GetPublicKey().GetN())
	e := int(bytesToBigInt(privKey.GetPublicKey().GetE()).Int64())
	hashType, err := protoAlgToHashType(privKey.GetPublicKey().GetAlgorithm())
	if err != nil {
		return nil, err
	}
	params, err := rsassapkcs1.NewParameters(n.BitLen(), hashType, e, rsassapkcs1.VariantNoPrefix)
	if err != nil {
		return nil, err
	}
	idRequirement := uint32(0)
	publicKey, err := rsassapkcs1.NewPublicKey(n.Bytes(), idRequirement, params)
	if err != nil {
		return nil, err
	}
	privateKey, err := rsassapkcs1.NewPrivateKey(publicKey, rsassapkcs1.PrivateKeyValues{
		P: secretdata.NewBytesFromData(privKey.GetP(), insecuresecretdataaccess.Token{}),
		Q: secretdata.NewBytesFromData(privKey.GetQ(), insecuresecretdataaccess.Token{}),
		D: secretdata.NewBytesFromData(privKey.GetD(), insecuresecretdataaccess.Token{}),
	})
	if err != nil {
		return nil, err
	}
	signer, err := rsassapkcs1.NewSigner(privateKey, internalapi.Token{})
	if err != nil {
		return nil, err
	}
	alg := privKey.GetPublicKey().GetAlgorithm()
	return newSignerWithKID(signer, alg.String(), rsCustomKID(privKey.GetPublicKey()))
}

func validateRSPrivateKey(privKey *jrsppb.JwtRsaSsaPkcs1PrivateKey) error {
	if err := keyset.ValidateKeyVersion(privKey.Version, jwtRSSignerKeyVersion); err != nil {
		return err
	}
	if privKey.GetD() == nil ||
		len(privKey.GetPublicKey().GetN()) == 0 ||
		len(privKey.GetPublicKey().GetE()) == 0 ||
		privKey.GetP() == nil ||
		privKey.GetQ() == nil ||
		privKey.GetDp() == nil ||
		privKey.GetDq() == nil ||
		privKey.GetCrt() == nil {
		return fmt.Errorf("invalid private key")
	}
	if err := validateRSPublicKey(privKey.GetPublicKey()); err != nil {
		return err
	}
	return nil
}

func (km *jwtRSSignerKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errRSInvalidKeyFormat
	}
	keyFormat := &jrsppb.JwtRsaSsaPkcs1KeyFormat{}
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JwtRsaSsaPkcs1KeyFormat: %v", err)
	}
	if err := keyset.ValidateKeyVersion(keyFormat.GetVersion(), jwtRSSignerKeyVersion); err != nil {
		return nil, err
	}
	if keyFormat.GetVersion() != jwtRSSignerKeyVersion {
		return nil, fmt.Errorf("invalid key format version: %d", keyFormat.GetVersion())
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, int(keyFormat.GetModulusSizeInBits()))
	if err != nil {
		return nil, err
	}
	privKey := &jrsppb.JwtRsaSsaPkcs1PrivateKey{
		Version: jwtRSSignerKeyVersion,
		PublicKey: &jrsppb.JwtRsaSsaPkcs1PublicKey{
			Version:   jwtRSSignerKeyVersion,
			Algorithm: keyFormat.GetAlgorithm(),
			N:         rsaKey.PublicKey.N.Bytes(),
			E:         keyFormat.GetPublicExponent(),
		},
		D:  rsaKey.D.Bytes(),
		P:  rsaKey.Primes[0].Bytes(),
		Q:  rsaKey.Primes[1].Bytes(),
		Dp: rsaKey.Precomputed.Dp.Bytes(),
		Dq: rsaKey.Precomputed.Dq.Bytes(),
		// In crypto/rsa `Qinv` is the "Chinese Remainder Theorem
		// coefficient q^(-1) mod p". This corresponds with `Crt` in
		// the Tink proto. This is unrelated to `CRTValues`, which
		// contains values specifically for additional primes, which
		// are not supported by Tink.
		Crt: rsaKey.Precomputed.Qinv.Bytes(),
	}
	if err := validateRSPrivateKey(privKey); err != nil {
		return nil, err
	}
	return privKey, nil
}

func (km *jwtRSSignerKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         jwtRSSignerTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

func (km *jwtRSSignerKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	if serializedPrivKey == nil {
		return nil, errRSInvalidKeyFormat
	}
	privKey := &jrsppb.JwtRsaSsaPkcs1PrivateKey{}
	if err := proto.Unmarshal(serializedPrivKey, privKey); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JwtRsaSsaPkcs1PrivateKey: %v", err)
	}
	if err := validateRSPrivateKey(privKey); err != nil {
		return nil, err
	}
	serializedPubKey, err := proto.Marshal(privKey.GetPublicKey())
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         jwtRSVerifierTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

func (km *jwtRSSignerKeyManager) DoesSupport(typeURL string) bool {
	return jwtRSSignerTypeURL == typeURL
}

func (km *jwtRSSignerKeyManager) TypeURL() string {
	return jwtRSSignerTypeURL
}
