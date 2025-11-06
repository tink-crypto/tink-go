// Copyright 2018 Google LLC
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

package ed25519_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	tinked25519 "github.com/tink-crypto/tink-go/v2/signature/ed25519"
	"github.com/tink-crypto/tink-go/v2/signature/subtle"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/testutil/testonlyinsecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"
	ed25519pb "github.com/tink-crypto/tink-go/v2/proto/ed25519_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestSignerKeyManagerGetPrimitiveBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.ED25519SignerTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.ED25519SignerTypeURL, err)
	}

	// Taken from https://datatracker.ietf.org/doc/html/rfc8032#section-7.1 - TEST 3.
	message := []byte{0xaf, 0x82}
	signatureHex := "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
	wantSignature, err := hex.DecodeString(signatureHex)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) err = %v, want nil", signatureHex, err)
	}
	params, err := tinked25519.NewParameters(tinked25519.VariantNoPrefix)
	if err != nil {
		t.Fatalf("tinked25519.NewParameters(%v) err = %v, want nil", tinked25519.VariantNoPrefix, err)
	}
	_, privateKeyBytes := getTestKeyPair(t)
	privateKey, err := tinked25519.NewPrivateKey(secretdata.NewBytesFromData(privateKeyBytes, testonlyinsecuresecretdataaccess.Token()), 0, params)
	if err != nil {
		t.Fatalf("tinked25519.NewPrivateKey(%v, %v, %v) err = %v, want nil", privateKeyBytes, 0, params, err)
	}

	keySerialization, err := protoserialization.SerializeKey(privateKey)
	if err != nil {
		t.Fatalf("protoserialization.SerializeKey(%v) err = %v, want nil", privateKey, err)
	}
	p, err := km.Primitive(keySerialization.KeyData().GetValue())
	if err != nil {
		t.Fatalf("km.Primitive(keySerialization.KeyData().GetValue()) err = %v, want nil", err)
	}
	s, ok := p.(tink.Signer)
	if !ok {
		t.Fatalf("km.Primitive(keySerialization.KeyData().GetValue()) = %T, want %T", p, (tink.Signer)(nil))
	}

	got, err := s.Sign(message)
	if err != nil {
		t.Fatalf("signer.Sign(%x) err = %v, want nil", message, err)
	}
	if diff := cmp.Diff(got, wantSignature); diff != "" {
		t.Errorf("signer.Sign() returned unexpected diff (-want +got):\n%s", diff)
	}
}

func TestSignerKeyManagerGetPrimitiveWithInvalidInput(t *testing.T) {
	// invalid params
	km, err := registry.GetKeyManager(testutil.ED25519SignerTypeURL)
	if err != nil {
		t.Errorf("cannot obtain ED25519Signer key manager: %s", err)
	}

	// invalid version
	key := testutil.NewED25519PrivateKey()
	key.Version = testutil.ED25519SignerKeyVersion + 1
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	if _, err := km.Primitive(serializedKey); err == nil {
		t.Errorf("expect an error when version is invalid")
	}
	// nil input
	if _, err := km.Primitive(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	if _, err := km.Primitive([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty slice")
	}
}

func TestSignerKeyManagerNewKeyBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.ED25519SignerTypeURL)
	if err != nil {
		t.Errorf("cannot obtain ED25519Signer key manager: %s", err)
	}
	serializedFormat, err := proto.Marshal(testutil.NewED25519PrivateKey())
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	tmp, err := km.NewKey(serializedFormat)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	key := tmp.(*ed25519pb.Ed25519PrivateKey)
	if err := validateED25519PrivateKey(key); err != nil {
		t.Errorf("invalid private key in test case: %s", err)
	}
}

func TestSignerKeyManagerPublicKeyDataBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.ED25519SignerTypeURL)
	if err != nil {
		t.Errorf("cannot obtain ED25519Signer key manager: %s", err)
	}
	pkm, ok := km.(registry.PrivateKeyManager)
	if !ok {
		t.Errorf("cannot obtain private key manager")
	}

	key := testutil.NewED25519PrivateKey()
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}

	pubKeyData, err := pkm.PublicKeyData(serializedKey)
	if err != nil {
		t.Errorf("unexpect error in test case: %s ", err)
	}
	if pubKeyData.TypeUrl != testutil.ED25519VerifierTypeURL {
		t.Errorf("incorrect type url: %s", pubKeyData.TypeUrl)
	}
	if pubKeyData.KeyMaterialType != tinkpb.KeyData_ASYMMETRIC_PUBLIC {
		t.Errorf("incorrect key material type: %d", pubKeyData.KeyMaterialType)
	}
	pubKey := new(ed25519pb.Ed25519PublicKey)
	if err = proto.Unmarshal(pubKeyData.Value, pubKey); err != nil {
		t.Errorf("invalid public key: %s", err)
	}
}

func TestSignerKeyManagerPublicKeyDataWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.ED25519SignerTypeURL)
	if err != nil {
		t.Errorf("cannot obtain ED25519Signer key manager: %s", err)
	}
	pkm, ok := km.(registry.PrivateKeyManager)
	if !ok {
		t.Errorf("cannot obtain private key manager")
	}
	// modified key
	key := testutil.NewED25519PrivateKey()
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	serializedKey[0] = 0
	if _, err := pkm.PublicKeyData(serializedKey); err == nil {
		t.Errorf("expect an error when input is a modified serialized key")
	}
	// invalid with a single byte
	if _, err := pkm.PublicKeyData([]byte{42}); err == nil {
		t.Errorf("expect an error when input is an empty slice")
	}
}

func validateED25519PrivateKey(key *ed25519pb.Ed25519PrivateKey) error {
	if key.Version != testutil.ED25519SignerKeyVersion {
		return fmt.Errorf("incorrect private key's version: expect %d, got %d",
			testutil.ED25519SignerKeyVersion, key.Version)
	}
	publicKey := key.PublicKey
	if publicKey.Version != testutil.ED25519SignerKeyVersion {
		return fmt.Errorf("incorrect public key's version: expect %d, got %d",
			testutil.ED25519SignerKeyVersion, key.Version)
	}

	signer, err := subtle.NewED25519Signer(key.KeyValue)
	if err != nil {
		return fmt.Errorf("unexpected error when creating ED25519Sign: %s", err)
	}

	verifier, err := subtle.NewED25519Verifier(publicKey.KeyValue)
	if err != nil {
		return fmt.Errorf("unexpected error when creating ED25519Verify: %s", err)
	}
	for i := 0; i < 100; i++ {
		data := random.GetRandomBytes(1281)
		signature, err := signer.Sign(data)
		if err != nil {
			return fmt.Errorf("unexpected error when signing: %s", err)
		}

		if err := verifier.Verify(signature, data); err != nil {
			return fmt.Errorf("unexpected error when verifying signature: %s", err)
		}
	}
	return nil
}
