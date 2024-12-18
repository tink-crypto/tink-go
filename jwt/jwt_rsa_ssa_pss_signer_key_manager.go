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

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapss"
	jrsppb "github.com/tink-crypto/tink-go/v2/proto/jwt_rsa_ssa_pss_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	jwtPSSignerKeyVersion = 0
	jwtPSSignerTypeURL    = "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPrivateKey"
)

var (
	errPSInvalidPrivateKey = errors.New("invalid JwtRsaSsaPssPrivateKey")
	errPSInvalidKeyFormat  = errors.New("invalid RSA SSA PSS key format")
)

// jwtPSSignerKeyManager implements the KeyManager interface
// for JWT Signing using the 'PS256', 'PS384', and 'PS512' JWA algorithm.
type jwtPSSignerKeyManager struct{}

var _ registry.PrivateKeyManager = (*jwtPSSignerKeyManager)(nil)

func protoRSASSAPSSAlgToHashType(algo jrsppb.JwtRsaSsaPssAlgorithm) (rsassapss.HashType, error) {
	switch algo {
	case jrsppb.JwtRsaSsaPssAlgorithm_PS256:
		return rsassapss.SHA256, nil
	case jrsppb.JwtRsaSsaPssAlgorithm_PS384:
		return rsassapss.SHA384, nil
	case jrsppb.JwtRsaSsaPssAlgorithm_PS512:
		return rsassapss.SHA512, nil
	default:
		return 0, fmt.Errorf("invalid algorithm: %v", algo)
	}
}

func (km *jwtPSSignerKeyManager) Primitive(serializedKey []byte) (any, error) {
	if serializedKey == nil {
		return nil, fmt.Errorf("invalid JwtRsaSsaPSSPrivateKey")
	}
	privKey := &jrsppb.JwtRsaSsaPssPrivateKey{}
	if err := proto.Unmarshal(serializedKey, privKey); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JwtRsaSsaPssPrivateKey: %v", err)
	}
	if err := validatePSPrivateKey(privKey); err != nil {
		return nil, err
	}

	saltLen := psAlgToSaltLen[privKey.GetPublicKey().GetAlgorithm()]
	hashType, err := protoRSASSAPSSAlgToHashType(privKey.GetPublicKey().GetAlgorithm())
	if err != nil {
		return nil, err
	}
	n := bytesToBigInt(privKey.GetPublicKey().GetN())
	e := int(bytesToBigInt(privKey.GetPublicKey().GetE()).Int64())
	params, err := rsassapss.NewParameters(rsassapss.ParametersValues{
		ModulusSizeBits: n.BitLen(),
		SigHashType:     hashType,
		MGF1HashType:    hashType,
		PublicExponent:  e,
		SaltLengthBytes: saltLen,
	}, rsassapss.VariantNoPrefix)
	if err != nil {
		return nil, err
	}
	idRequirement := uint32(0)
	publicKey, err := rsassapss.NewPublicKey(n.Bytes(), idRequirement, params)
	if err != nil {
		return nil, err
	}
	privateKey, err := rsassapss.NewPrivateKey(publicKey, rsassapss.PrivateKeyValues{
		P: secretdata.NewBytesFromData(privKey.GetP(), insecuresecretdataaccess.Token{}),
		Q: secretdata.NewBytesFromData(privKey.GetQ(), insecuresecretdataaccess.Token{}),
		D: secretdata.NewBytesFromData(privKey.GetD(), insecuresecretdataaccess.Token{}),
	})
	if err != nil {
		return nil, err
	}
	signer, err := rsassapss.NewSigner(privateKey, internalapi.Token{})
	if err != nil {
		return nil, err
	}
	alg := privKey.GetPublicKey().GetAlgorithm()
	return newSignerWithKID(signer, alg.String(), psCustomKID(privKey.GetPublicKey()))
}

func validatePSPrivateKey(privKey *jrsppb.JwtRsaSsaPssPrivateKey) error {
	if err := keyset.ValidateKeyVersion(privKey.Version, jwtPSSignerKeyVersion); err != nil {
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
	if err := validatePSPublicKey(privKey.GetPublicKey()); err != nil {
		return err
	}
	return nil
}

func (km *jwtPSSignerKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errPSInvalidKeyFormat
	}
	keyFormat := &jrsppb.JwtRsaSsaPssKeyFormat{}
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JwtRsaSsaPssKeyFormat: %v", err)
	}
	if err := keyset.ValidateKeyVersion(keyFormat.GetVersion(), jwtPSSignerKeyVersion); err != nil {
		return nil, err
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, int(keyFormat.GetModulusSizeInBits()))
	if err != nil {
		return nil, err
	}
	privKey := &jrsppb.JwtRsaSsaPssPrivateKey{
		Version: jwtPSSignerKeyVersion,
		PublicKey: &jrsppb.JwtRsaSsaPssPublicKey{
			Version:   jwtPSSignerKeyVersion,
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
	if err := validatePSPrivateKey(privKey); err != nil {
		return nil, err
	}
	return privKey, nil
}

func (km *jwtPSSignerKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         jwtPSSignerTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

func (km *jwtPSSignerKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	if serializedPrivKey == nil {
		return nil, errPSInvalidKeyFormat
	}
	privKey := &jrsppb.JwtRsaSsaPssPrivateKey{}
	if err := proto.Unmarshal(serializedPrivKey, privKey); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JwtRsaSsaPssPrivateKey: %v", err)
	}
	if err := validatePSPrivateKey(privKey); err != nil {
		return nil, err
	}
	serializedPubKey, err := proto.Marshal(privKey.GetPublicKey())
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         jwtPSVerifierTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

func (km *jwtPSSignerKeyManager) DoesSupport(typeURL string) bool {
	return jwtPSSignerTypeURL == typeURL
}

func (km *jwtPSSignerKeyManager) TypeURL() string {
	return jwtPSSignerTypeURL
}
