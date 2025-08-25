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

// Package jwk provides functions to convert between JWK and Tink keysets.
package jwk

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"math/rand"

	spb "google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/keyset"
	ed25519pb "github.com/tink-crypto/tink-go/v2/proto/ed25519_go_proto"
	jepb "github.com/tink-crypto/tink-go/v2/proto/jwt_ecdsa_go_proto"
	jrsppb "github.com/tink-crypto/tink-go/v2/proto/jwt_rsa_ssa_pkcs1_go_proto"
	jrpsspb "github.com/tink-crypto/tink-go/v2/proto/jwt_rsa_ssa_pss_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	jwtECDSAPublicKeyType = "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey"
	jwtRSPublicKeyType    = "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey"
	jwtPSPublicKeyType    = "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey"

	ed25519PublicKeyType = "type.googleapis.com/google.crypto.tink.Ed25519PublicKey"
)

// Ed25519SupportType is an enum to control Ed25519 key conversion.
type Ed25519SupportType int

const (
	// Ed25519SupportNone means Ed25519 keys are not supported and will return an error.
	Ed25519SupportNone Ed25519SupportType = iota
	// Ed25519SupportTink means Ed25519 keys are supported and will be converted to Tink keys.
	Ed25519SupportTink
)

func keysetHasID(ks *tinkpb.Keyset, keyID uint32) bool {
	for _, k := range ks.GetKey() {
		if k.GetKeyId() == keyID {
			return true
		}
	}
	return false
}

func generateUnusedID(ks *tinkpb.Keyset) uint32 {
	for {
		keyID := rand.Uint32()
		if !keysetHasID(ks, keyID) {
			return keyID
		}
	}
}

func hasItem(s *spb.Struct, name string) bool {
	if s.GetFields() == nil {
		return false
	}
	_, ok := s.Fields[name]
	return ok
}

func stringItem(s *spb.Struct, name string) (string, error) {
	fields := s.GetFields()
	if fields == nil {
		return "", fmt.Errorf("no fields")
	}
	val, ok := fields[name]
	if !ok {
		return "", fmt.Errorf("field %q not found", name)
	}
	r, ok := val.Kind.(*spb.Value_StringValue)
	if !ok {
		return "", fmt.Errorf("field %q is not a string", name)
	}
	return r.StringValue, nil
}

func listValue(s *spb.Struct, name string) (*spb.ListValue, error) {
	fields := s.GetFields()
	if fields == nil {
		return nil, fmt.Errorf("empty set")
	}
	vals, ok := fields[name]
	if !ok {
		return nil, fmt.Errorf("%q not found", name)
	}
	list, ok := vals.Kind.(*spb.Value_ListValue)
	if !ok {
		return nil, fmt.Errorf("%q is not a list", name)
	}
	if list.ListValue == nil || len(list.ListValue.GetValues()) == 0 {
		return nil, fmt.Errorf("%q list is empty", name)
	}
	return list.ListValue, nil
}

func expectStringItem(s *spb.Struct, name, value string) error {
	item, err := stringItem(s, name)
	if err != nil {
		return err
	}
	if item != value {
		return fmt.Errorf("unexpected value %q for %q", value, name)
	}
	return nil
}

func decodeItem(s *spb.Struct, name string) ([]byte, error) {
	e, err := stringItem(s, name)
	if err != nil {
		return nil, err
	}
	return base64Decode(e)
}

func validateKeyOPSIsVerify(s *spb.Struct) error {
	if !hasItem(s, "key_ops") {
		return nil
	}
	keyOPSList, err := listValue(s, "key_ops")
	if err != nil {
		return err
	}
	if len(keyOPSList.GetValues()) != 1 {
		return fmt.Errorf("key_ops size is not 1")
	}
	value, ok := keyOPSList.GetValues()[0].Kind.(*spb.Value_StringValue)
	if !ok {
		return fmt.Errorf("key_ops is not a string")
	}
	if value.StringValue != "verify" {
		return fmt.Errorf("key_ops is not equal to [\"verify\"]")
	}
	return nil
}

func validateUseIsSig(s *spb.Struct) error {
	if !hasItem(s, "use") {
		return nil
	}
	return expectStringItem(s, "use", "sig")
}

func algorithmPrefix(s *spb.Struct) (string, error) {
	alg, err := stringItem(s, "alg")
	if err != nil {
		return "", err
	}
	if len(alg) < 2 {
		return "", fmt.Errorf("invalid algorithm")
	}
	return alg[0:2], nil
}

var psNameToAlg = map[string]jrpsspb.JwtRsaSsaPssAlgorithm{
	"PS256": jrpsspb.JwtRsaSsaPssAlgorithm_PS256,
	"PS384": jrpsspb.JwtRsaSsaPssAlgorithm_PS384,
	"PS512": jrpsspb.JwtRsaSsaPssAlgorithm_PS512,
}

func psPublicKeyDataFromStruct(keyStruct *spb.Struct) (*tinkpb.KeyData, error) {
	alg, err := stringItem(keyStruct, "alg")
	if err != nil {
		return nil, err
	}
	algorithm, ok := psNameToAlg[alg]
	if !ok {
		return nil, fmt.Errorf("invalid alg header: %q", alg)
	}
	rsaPubKey, err := rsaPubKeyFromStruct(keyStruct)
	if err != nil {
		return nil, err
	}
	jwtPubKey := &jrpsspb.JwtRsaSsaPssPublicKey{
		Version:   0,
		Algorithm: algorithm,
		E:         rsaPubKey.exponent,
		N:         rsaPubKey.modulus,
	}
	if rsaPubKey.customKID != nil {
		jwtPubKey.CustomKid = &jrpsspb.JwtRsaSsaPssPublicKey_CustomKid{
			Value: *rsaPubKey.customKID,
		}
	}
	serializedPubKey, err := proto.Marshal(jwtPubKey)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         jwtPSPublicKeyType,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

var rsNameToAlg = map[string]jrsppb.JwtRsaSsaPkcs1Algorithm{
	"RS256": jrsppb.JwtRsaSsaPkcs1Algorithm_RS256,
	"RS384": jrsppb.JwtRsaSsaPkcs1Algorithm_RS384,
	"RS512": jrsppb.JwtRsaSsaPkcs1Algorithm_RS512,
}

func rsPublicKeyDataFromStruct(keyStruct *spb.Struct) (*tinkpb.KeyData, error) {
	alg, err := stringItem(keyStruct, "alg")
	if err != nil {
		return nil, err
	}
	algorithm, ok := rsNameToAlg[alg]
	if !ok {
		return nil, fmt.Errorf("invalid alg header: %q", alg)
	}
	rsaPubKey, err := rsaPubKeyFromStruct(keyStruct)
	if err != nil {
		return nil, err
	}
	jwtPubKey := &jrsppb.JwtRsaSsaPkcs1PublicKey{
		Version:   0,
		Algorithm: algorithm,
		E:         rsaPubKey.exponent,
		N:         rsaPubKey.modulus,
	}
	if rsaPubKey.customKID != nil {
		jwtPubKey.CustomKid = &jrsppb.JwtRsaSsaPkcs1PublicKey_CustomKid{
			Value: *rsaPubKey.customKID,
		}
	}
	serializedPubKey, err := proto.Marshal(jwtPubKey)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         jwtRSPublicKeyType,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

type rsaPubKey struct {
	exponent  []byte
	modulus   []byte
	customKID *string
}

func rsaPubKeyFromStruct(keyStruct *spb.Struct) (*rsaPubKey, error) {
	if hasItem(keyStruct, "p") ||
		hasItem(keyStruct, "q") ||
		hasItem(keyStruct, "dq") ||
		hasItem(keyStruct, "dp") ||
		hasItem(keyStruct, "d") ||
		hasItem(keyStruct, "qi") {
		return nil, fmt.Errorf("private key can't be converted")
	}
	if err := expectStringItem(keyStruct, "kty", "RSA"); err != nil {
		return nil, err
	}
	if err := validateUseIsSig(keyStruct); err != nil {
		return nil, err
	}
	if err := validateKeyOPSIsVerify(keyStruct); err != nil {
		return nil, err
	}
	e, err := decodeItem(keyStruct, "e")
	if err != nil {
		return nil, err
	}
	n, err := decodeItem(keyStruct, "n")
	if err != nil {
		return nil, err
	}
	var customKID *string = nil
	if hasItem(keyStruct, "kid") {
		kid, err := stringItem(keyStruct, "kid")
		if err != nil {
			return nil, err
		}
		customKID = &kid
	}
	return &rsaPubKey{
		exponent:  e,
		modulus:   n,
		customKID: customKID,
	}, nil
}

func esPublicKeyDataFromStruct(keyStruct *spb.Struct) (*tinkpb.KeyData, error) {
	alg, err := stringItem(keyStruct, "alg")
	if err != nil {
		return nil, err
	}
	curve, err := stringItem(keyStruct, "crv")
	if err != nil {
		return nil, err
	}
	var algorithm jepb.JwtEcdsaAlgorithm = jepb.JwtEcdsaAlgorithm_ES_UNKNOWN
	if alg == "ES256" && curve == "P-256" {
		algorithm = jepb.JwtEcdsaAlgorithm_ES256
	}
	if alg == "ES384" && curve == "P-384" {
		algorithm = jepb.JwtEcdsaAlgorithm_ES384
	}
	if alg == "ES512" && curve == "P-521" {
		algorithm = jepb.JwtEcdsaAlgorithm_ES512
	}
	if algorithm == jepb.JwtEcdsaAlgorithm_ES_UNKNOWN {
		return nil, fmt.Errorf("invalid algorithm %q and curve %q", alg, curve)
	}
	if hasItem(keyStruct, "d") {
		return nil, fmt.Errorf("private keys cannot be converted")
	}
	if err := expectStringItem(keyStruct, "kty", "EC"); err != nil {
		return nil, err
	}
	if err := validateUseIsSig(keyStruct); err != nil {
		return nil, err
	}
	if err := validateKeyOPSIsVerify(keyStruct); err != nil {
		return nil, err
	}
	x, err := decodeItem(keyStruct, "x")
	if err != nil {
		return nil, fmt.Errorf("failed to decode x: %v", err)
	}
	y, err := decodeItem(keyStruct, "y")
	if err != nil {
		return nil, fmt.Errorf("failed to decode y: %v", err)
	}
	var customKID *jepb.JwtEcdsaPublicKey_CustomKid = nil
	if hasItem(keyStruct, "kid") {
		kid, err := stringItem(keyStruct, "kid")
		if err != nil {
			return nil, err
		}
		customKID = &jepb.JwtEcdsaPublicKey_CustomKid{Value: kid}
	}
	pubKey := &jepb.JwtEcdsaPublicKey{
		Version:   0,
		Algorithm: algorithm,
		X:         x,
		Y:         y,
		CustomKid: customKID,
	}
	serializedPubKey, err := proto.Marshal(pubKey)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         jwtECDSAPublicKeyType,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

func ed25519PublicKeyDataFromStruct(keyStruct *spb.Struct) (*tinkpb.KeyData, error) {
	if err := expectStringItem(keyStruct, "kty", "OKP"); err != nil {
		return nil, err
	}
	if err := expectStringItem(keyStruct, "crv", "Ed25519"); err != nil {
		return nil, err
	}
	if err := validateUseIsSig(keyStruct); err != nil {
		return nil, err
	}
	if err := validateKeyOPSIsVerify(keyStruct); err != nil {
		return nil, err
	}
	x, err := decodeItem(keyStruct, "x")
	if err != nil {
		return nil, fmt.Errorf("failed to decode x: %v", err)
	}
	pubKey := &ed25519pb.Ed25519PublicKey{
		Version:  0,
		KeyValue: x,
	}
	serializedPubKey, err := proto.Marshal(pubKey)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         ed25519PublicKeyType,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

func keysetKeyFromStruct(val *spb.Value, keyID uint32, ed25519Support Ed25519SupportType) (*tinkpb.Keyset_Key, error) {
	keyStruct := val.GetStructValue()
	if keyStruct == nil {
		return nil, fmt.Errorf("key is not a JSON object")
	}
	algPrefix, err := algorithmPrefix(keyStruct)
	if err != nil {
		return nil, err
	}
	var keyData *tinkpb.KeyData
	switch algPrefix {
	case "ES":
		keyData, err = esPublicKeyDataFromStruct(keyStruct)
	case "RS":
		keyData, err = rsPublicKeyDataFromStruct(keyStruct)
	case "PS":
		keyData, err = psPublicKeyDataFromStruct(keyStruct)
	case "Ed":
		if keyStruct.GetFields()["crv"].GetStringValue() == "Ed25519" && ed25519Support == Ed25519SupportTink {
			keyData, err = ed25519PublicKeyDataFromStruct(keyStruct)
		} else {
			return nil, fmt.Errorf("Ed25519 is not supported")
		}
	default:
		return nil, fmt.Errorf("unsupported algorithm prefix: %v", algPrefix)
	}
	if err != nil {
		return nil, err
	}
	return &tinkpb.Keyset_Key{
		KeyData:          keyData,
		Status:           tinkpb.KeyStatusType_ENABLED,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
		KeyId:            keyID,
	}, nil
}

// ToPublicKeysetHandle converts a Json Web Key (JWK) set into a Tink public KeysetHandle.
// It requires that all keys in the set have the "alg" field set. Currently, only
// public keys for algorithms ES256, ES384, ES512, RS256, RS384, RS512 are supported.
// Ed25519 is supported, but it will return a Tink Verification Key instead of JWT verification.
// TODO - b/436348879: separate JWK Signature and JWT conversions.
// JWK is defined in https://www.rfc-editor.org/rfc/rfc7517.txt.
func ToPublicKeysetHandle(jwkSet []byte, ed25519Support Ed25519SupportType) (*keyset.Handle, error) {
	jwk := &spb.Struct{}
	if err := jwk.UnmarshalJSON(jwkSet); err != nil {
		return nil, err
	}
	keyList, err := listValue(jwk, "keys")
	if err != nil {
		return nil, err
	}

	ks := &tinkpb.Keyset{}
	for _, keyStruct := range keyList.GetValues() {
		key, err := keysetKeyFromStruct(keyStruct, generateUnusedID(ks), ed25519Support)
		if err != nil {
			return nil, err
		}
		ks.Key = append(ks.Key, key)
	}
	ks.PrimaryKeyId = ks.Key[len(ks.Key)-1].GetKeyId()
	return keyset.NewHandleWithNoSecrets(ks)
}

func addKeyOPSVerify(s *spb.Struct) {
	s.GetFields()["key_ops"] = spb.NewListValue(&spb.ListValue{Values: []*spb.Value{spb.NewStringValue("verify")}})
}

func addStringEntry(s *spb.Struct, key, val string) {
	s.GetFields()[key] = spb.NewStringValue(val)
}

var psAlgToStr map[jrpsspb.JwtRsaSsaPssAlgorithm]string = map[jrpsspb.JwtRsaSsaPssAlgorithm]string{
	jrpsspb.JwtRsaSsaPssAlgorithm_PS256: "PS256",
	jrpsspb.JwtRsaSsaPssAlgorithm_PS384: "PS384",
	jrpsspb.JwtRsaSsaPssAlgorithm_PS512: "PS512",
}

func psPublicKeyToStruct(key *tinkpb.Keyset_Key) (*spb.Struct, error) {
	pubKey := &jrpsspb.JwtRsaSsaPssPublicKey{}
	if err := proto.Unmarshal(key.GetKeyData().GetValue(), pubKey); err != nil {
		return nil, err
	}
	alg, ok := psAlgToStr[pubKey.GetAlgorithm()]
	if !ok {
		return nil, fmt.Errorf("invalid algorithm")
	}
	outKey := &spb.Struct{
		Fields: map[string]*spb.Value{},
	}
	addStringEntry(outKey, "alg", alg)
	addStringEntry(outKey, "kty", "RSA")
	addStringEntry(outKey, "e", base64Encode(pubKey.GetE()))
	addStringEntry(outKey, "n", base64Encode(pubKey.GetN()))
	addStringEntry(outKey, "use", "sig")
	addKeyOPSVerify(outKey)
	var customKID *string = nil
	if pubKey.GetCustomKid() != nil {
		ck := pubKey.GetCustomKid().GetValue()
		customKID = &ck
	}
	if err := setKeyID(outKey, key, customKID); err != nil {
		return nil, err
	}
	return outKey, nil
}

var rsAlgToStr map[jrsppb.JwtRsaSsaPkcs1Algorithm]string = map[jrsppb.JwtRsaSsaPkcs1Algorithm]string{
	jrsppb.JwtRsaSsaPkcs1Algorithm_RS256: "RS256",
	jrsppb.JwtRsaSsaPkcs1Algorithm_RS384: "RS384",
	jrsppb.JwtRsaSsaPkcs1Algorithm_RS512: "RS512",
}

func rsPublicKeyToStruct(key *tinkpb.Keyset_Key) (*spb.Struct, error) {
	pubKey := &jrsppb.JwtRsaSsaPkcs1PublicKey{}
	if err := proto.Unmarshal(key.GetKeyData().GetValue(), pubKey); err != nil {
		return nil, err
	}
	alg, ok := rsAlgToStr[pubKey.GetAlgorithm()]
	if !ok {
		return nil, fmt.Errorf("invalid algorithm")
	}
	outKey := &spb.Struct{
		Fields: map[string]*spb.Value{},
	}
	addStringEntry(outKey, "alg", alg)
	addStringEntry(outKey, "kty", "RSA")
	addStringEntry(outKey, "e", base64Encode(pubKey.GetE()))
	addStringEntry(outKey, "n", base64Encode(pubKey.GetN()))
	addStringEntry(outKey, "use", "sig")
	addKeyOPSVerify(outKey)

	var customKID *string = nil
	if pubKey.GetCustomKid() != nil {
		ck := pubKey.GetCustomKid().GetValue()
		customKID = &ck
	}
	if err := setKeyID(outKey, key, customKID); err != nil {
		return nil, err
	}
	return outKey, nil
}

func esPublicKeyToStruct(key *tinkpb.Keyset_Key) (*spb.Struct, error) {
	pubKey := &jepb.JwtEcdsaPublicKey{}
	if err := proto.Unmarshal(key.GetKeyData().GetValue(), pubKey); err != nil {
		return nil, err
	}
	outKey := &spb.Struct{
		Fields: map[string]*spb.Value{},
	}
	var algorithm, curve string
	var encLen int
	switch pubKey.GetAlgorithm() {
	case jepb.JwtEcdsaAlgorithm_ES256:
		curve, algorithm, encLen = "P-256", "ES256", 32
	case jepb.JwtEcdsaAlgorithm_ES384:
		curve, algorithm, encLen = "P-384", "ES384", 48
	case jepb.JwtEcdsaAlgorithm_ES512:
		curve, algorithm, encLen = "P-521", "ES512", 66
	default:
		return nil, fmt.Errorf("invalid algorithm")
	}

	// RFC 7518 specifies a fixed sized encoding for the x and y coordinates from SEC 1
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.2
	xi := big.NewInt(0).SetBytes(pubKey.GetX())
	if xi.BitLen() > encLen*8 {
		return nil, fmt.Errorf("invalid x coordinate")
	}
	x := xi.FillBytes(make([]byte, encLen))
	yi := big.NewInt(0).SetBytes(pubKey.GetY())
	if yi.BitLen() > encLen*8 {
		return nil, fmt.Errorf("invalid y coordinate")
	}
	y := yi.FillBytes(make([]byte, encLen))

	addStringEntry(outKey, "crv", curve)
	addStringEntry(outKey, "alg", algorithm)
	addStringEntry(outKey, "kty", "EC")
	addStringEntry(outKey, "x", base64Encode(x))
	addStringEntry(outKey, "y", base64Encode(y))
	addStringEntry(outKey, "use", "sig")
	addKeyOPSVerify(outKey)

	var customKID *string = nil
	if pubKey.GetCustomKid() != nil {
		ck := pubKey.GetCustomKid().GetValue()
		customKID = &ck
	}
	if err := setKeyID(outKey, key, customKID); err != nil {
		return nil, err
	}
	return outKey, nil
}

func ed25519PublicKeyToStruct(key *tinkpb.Keyset_Key) (*spb.Struct, error) {
	pubKey := &ed25519pb.Ed25519PublicKey{}
	if err := proto.Unmarshal(key.GetKeyData().GetValue(), pubKey); err != nil {
		return nil, err
	}
	outKey := &spb.Struct{
		Fields: map[string]*spb.Value{},
	}
	addStringEntry(outKey, "kty", "OKP")
	addStringEntry(outKey, "crv", "Ed25519")
	addStringEntry(outKey, "alg", "EdDSA")
	addStringEntry(outKey, "x", base64Encode(pubKey.GetKeyValue()))
	addStringEntry(outKey, "use", "sig")
	addKeyOPSVerify(outKey)

	if err := setKeyID(outKey, key, nil); err != nil {
		return nil, err
	}
	return outKey, nil
}

func setKeyID(outKey *spb.Struct, key *tinkpb.Keyset_Key, customKID *string) error {
	if key.GetOutputPrefixType() == tinkpb.OutputPrefixType_TINK {
		if customKID != nil {
			return fmt.Errorf("TINK keys shouldn't have custom KID")
		}
		kid := keyID(key.KeyId, key.GetOutputPrefixType())
		if kid == nil {
			return fmt.Errorf("tink KID shouldn't be nil")
		}
		addStringEntry(outKey, "kid", *kid)
	} else if customKID != nil {
		addStringEntry(outKey, "kid", *customKID)
	}
	return nil
}

// FromPublicKeysetHandle converts a Tink KeysetHandle into a Json Web Key (JWK) set.
// Currently only public keys for algorithms ES256, ES384, ES512, RS256, RS384, RS512 are supported.
// Ed25519 is supported, but it will return a Tink Verification Key instead of JWT verification.
// TODO - b/436348879: separate JWK Signature and JWT conversions.
// JWK is defined in https://www.rfc-editor.org/rfc/rfc7517.html.
func FromPublicKeysetHandle(kh *keyset.Handle, ed25519Support Ed25519SupportType) ([]byte, error) {
	b := &bytes.Buffer{}
	if err := kh.WriteWithNoSecrets(keyset.NewBinaryWriter(b)); err != nil {
		return nil, err
	}
	ks := &tinkpb.Keyset{}
	if err := proto.Unmarshal(b.Bytes(), ks); err != nil {
		return nil, err
	}
	keyValList := []*spb.Value{}
	for _, k := range ks.Key {
		if k.GetStatus() != tinkpb.KeyStatusType_ENABLED {
			continue
		}
		if k.GetOutputPrefixType() != tinkpb.OutputPrefixType_TINK &&
			k.GetOutputPrefixType() != tinkpb.OutputPrefixType_RAW {
			return nil, fmt.Errorf("unsupported output prefix type")
		}
		keyData := k.GetKeyData()
		if keyData == nil {
			return nil, fmt.Errorf("invalid key data")
		}
		if keyData.GetKeyMaterialType() != tinkpb.KeyData_ASYMMETRIC_PUBLIC {
			return nil, fmt.Errorf("only asymmetric public keys are supported")
		}
		keyStruct := &spb.Struct{}
		var err error
		switch keyData.GetTypeUrl() {
		case jwtECDSAPublicKeyType:
			keyStruct, err = esPublicKeyToStruct(k)
		case jwtRSPublicKeyType:
			keyStruct, err = rsPublicKeyToStruct(k)
		case jwtPSPublicKeyType:
			keyStruct, err = psPublicKeyToStruct(k)
		case ed25519PublicKeyType:
			if ed25519Support == Ed25519SupportNone {
				return nil, fmt.Errorf("Ed25519 keys are not supported")
			}
			keyStruct, err = ed25519PublicKeyToStruct(k)
		default:
			return nil, fmt.Errorf("unsupported key type url, %s", keyData.GetTypeUrl())
		}
		if err != nil {
			return nil, err
		}
		keyValList = append(keyValList, spb.NewStructValue(keyStruct))
	}
	output := &spb.Struct{
		Fields: map[string]*spb.Value{
			"keys": spb.NewListValue(&spb.ListValue{Values: keyValList}),
		},
	}
	return output.MarshalJSON()
}

// From google3/third_party/tink/go/jwt/jwt_encoding.go

// base64Encode encodes a byte array into a base64 URL safe string with no padding.
func base64Encode(content []byte) string {
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(content)
}

// base64Decode decodes a URL safe base64 encoded string into a byte array ignoring padding.
func base64Decode(content string) ([]byte, error) {
	for _, c := range content {
		if !isValidURLsafeBase64Char(c) {
			return nil, fmt.Errorf("invalid encoding")
		}
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(content)
}

func isValidURLsafeBase64Char(c rune) bool {
	return (((c >= 'a') && (c <= 'z')) || ((c >= 'A') && (c <= 'Z')) ||
		((c >= '0') && (c <= '9')) || ((c == '-') || (c == '_')))
}

// keyID returns the keyID in big endian format base64 encoded if the key output prefix is of type Tink or nil otherwise.
func keyID(keyID uint32, outPrefixType tinkpb.OutputPrefixType) *string {
	if outPrefixType != tinkpb.OutputPrefixType_TINK {
		return nil
	}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, keyID)
	s := base64Encode(buf)
	return &s
}
