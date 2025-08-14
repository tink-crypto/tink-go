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

package jwt_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/internalregistry"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveregistry"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/monitoring"
	"github.com/tink-crypto/tink-go/v2/signature"
	"github.com/tink-crypto/tink-go/v2/testing/fakemonitoring"
	"github.com/tink-crypto/tink-go/v2/testkeyset"
	"github.com/tink-crypto/tink-go/v2/testutil"
	jepb "github.com/tink-crypto/tink-go/v2/proto/jwt_ecdsa_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestSignerVerifierFactoryWithInvalidPrimitiveSetType(t *testing.T) {
	kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("failed to build *keyset.Handle: %s", err)
	}
	if _, err := jwt.NewSigner(kh); err == nil {
		t.Errorf("jwt.NewSigner() err = nil, want error")
	}
	if _, err := jwt.NewVerifier(kh); err == nil {
		t.Errorf("jwt.NewVerifier() err = nil, want error")
	}
}

func TestSignerVerifierFactoryNilKeyset(t *testing.T) {
	if _, err := jwt.NewSigner(nil); err == nil {
		t.Errorf("jwt.NewSigner(nil) err = nil, want error")
	}
	if _, err := jwt.NewVerifier(nil); err == nil {
		t.Errorf("jwt.NewVerifier(nil) err = nil, want error")
	}
}

func createJWTECDSAKey(kid *string) (*jepb.JwtEcdsaPrivateKey, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdsa.GenerateKey(curve=P256): %v", err)
	}
	var customKID *jepb.JwtEcdsaPublicKey_CustomKid = nil
	if kid != nil {
		customKID = &jepb.JwtEcdsaPublicKey_CustomKid{Value: *kid}
	}
	return &jepb.JwtEcdsaPrivateKey{
		Version: 0,
		PublicKey: &jepb.JwtEcdsaPublicKey{
			Version:   0,
			Algorithm: jepb.JwtEcdsaAlgorithm_ES256,
			X:         k.X.Bytes(),
			Y:         k.Y.Bytes(),
			CustomKid: customKID,
		},
		KeyValue: k.D.Bytes(),
	}, nil
}

func createKeyData(privKey *jepb.JwtEcdsaPrivateKey) (*tinkpb.KeyData, error) {
	serializedPrivKey, err := proto.Marshal(privKey)
	if err != nil {
		return nil, fmt.Errorf("serializing private key proto: %v", err)
	}
	return &tinkpb.KeyData{
		TypeUrl:         "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
		Value:           serializedPrivKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

func createKeysetHandles(privKey *tinkpb.KeyData, outputPrefixType tinkpb.OutputPrefixType) (*keyset.Handle, *keyset.Handle, error) {
	k := testutil.NewKey(privKey, tinkpb.KeyStatusType_ENABLED, 1 /*=keyID*/, outputPrefixType)
	privKeyHandle, err := testkeyset.NewHandle(testutil.NewKeyset(k.KeyId, []*tinkpb.Keyset_Key{k}))
	if err != nil {
		return nil, nil, fmt.Errorf("creating keyset handle for private key: %v", err)
	}
	pubKeyHandle, err := privKeyHandle.Public()
	if err != nil {
		return nil, nil, fmt.Errorf("creating keyset handle for public key: %v", err)
	}
	return privKeyHandle, pubKeyHandle, nil
}

func createKeyHandlesFromKey(t *testing.T, privKey *jepb.JwtEcdsaPrivateKey, outputPrefixType tinkpb.OutputPrefixType) (*keyset.Handle, *keyset.Handle) {
	privKeyData, err := createKeyData(privKey)
	if err != nil {
		t.Fatal(err)
	}
	privKeyHandle, pubKeyHandle, err := createKeysetHandles(privKeyData, outputPrefixType)
	if err != nil {
		t.Fatal(err)
	}
	return privKeyHandle, pubKeyHandle
}

func createKeyAndKeyHandles(t *testing.T, kid *string, outputPrefixType tinkpb.OutputPrefixType) (*jepb.JwtEcdsaPrivateKey, *keyset.Handle, *keyset.Handle) {
	privKey, err := createJWTECDSAKey(kid)
	if err != nil {
		t.Fatal(err)
	}
	privKeyHandle, pubKeyHandle := createKeyHandlesFromKey(t, privKey, outputPrefixType)
	return privKey, privKeyHandle, pubKeyHandle
}

func TestFactoryVerifyWithDifferentKeyFails(t *testing.T) {
	_, privKeyHandle, pubKeyHandle := createKeyAndKeyHandles(t, nil /*=kid*/, tinkpb.OutputPrefixType_TINK)

	signer, err := jwt.NewSigner(privKeyHandle)
	if err != nil {
		t.Fatalf("jwt.NewSigner() err = %v, want nil", err)
	}
	verifier, err := jwt.NewVerifier(pubKeyHandle)
	if err != nil {
		t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
	}

	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true, Audiences: []string{"tink-audience"}})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true, ExpectedAudience: refString("tink-audience")})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	compact, err := signer.SignAndEncode(rawJWT)
	if err != nil {
		t.Errorf("signer.SignAndEncode() err = %v, want nil", err)
	}
	if _, err := verifier.VerifyAndDecode(compact, validator); err != nil {
		t.Errorf("verifier.VerifyAndDecode() err = %v, want nil", err)
	}

	// verification with different key fails
	_, _, pubKeyHandle = createKeyAndKeyHandles(t, nil /*=kid*/, tinkpb.OutputPrefixType_TINK)
	verifier, err = jwt.NewVerifier(pubKeyHandle)
	if err != nil {
		t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
	}
	if _, err := verifier.VerifyAndDecode(compact, validator); err == nil {
		t.Errorf("verifier.VerifyAndDecode() err = nil, want error")
	}
}

type signerVerifierFactoryKIDTestCase struct {
	tag                  string
	signerOutputPrefix   tinkpb.OutputPrefixType
	signerKID            *string
	verifierOutputPrefix tinkpb.OutputPrefixType
	verifierKID          *string
}

func TestFactorySignVerifyWithKIDFailure(t *testing.T) {
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	for _, tc := range []signerVerifierFactoryKIDTestCase{
		{
			tag:                  "raw output prefix and different custom kid",
			signerOutputPrefix:   tinkpb.OutputPrefixType_RAW,
			signerKID:            refString("customKID"),
			verifierOutputPrefix: tinkpb.OutputPrefixType_RAW,
			verifierKID:          refString("OtherCustomKID"),
		},
		{
			tag:                  "token with fixed kid and verifier with tink output prefix",
			signerOutputPrefix:   tinkpb.OutputPrefixType_RAW,
			signerKID:            refString("customKID"),
			verifierOutputPrefix: tinkpb.OutputPrefixType_TINK,
			verifierKID:          nil,
		},
		{
			tag:                  "token missing kid in header when verifier has tink output prefix",
			signerOutputPrefix:   tinkpb.OutputPrefixType_RAW,
			signerKID:            nil,
			verifierOutputPrefix: tinkpb.OutputPrefixType_TINK,
			verifierKID:          nil,
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			key, privKeyHandle, _ := createKeyAndKeyHandles(t, tc.signerKID, tc.signerOutputPrefix)
			signer, err := jwt.NewSigner(privKeyHandle)
			if err != nil {
				t.Fatalf("jwt.NewSigner() err = %v, want nil", err)
			}
			compact, err := signer.SignAndEncode(rawJWT)
			if err != nil {
				t.Errorf("signer.SignAndEncode() err = %v, want nil", err)
			}

			key.PublicKey.CustomKid = nil
			if tc.verifierKID != nil {
				key.PublicKey.CustomKid = &jepb.JwtEcdsaPublicKey_CustomKid{Value: *tc.verifierKID}
			}
			_, pubKeyHandle := createKeyHandlesFromKey(t, key, tc.verifierOutputPrefix)
			verifier, err := jwt.NewVerifier(pubKeyHandle)
			if err != nil {
				t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
			}
			if _, err := verifier.VerifyAndDecode(compact, validator); err == nil {
				t.Errorf("verifier.VerifyAndDecode() err = nil, want error")
			}
		})
	}
}

func TestVerifyAndDecodeReturnsValidationError(t *testing.T) {
	_, privateHandle, publicHandle := createKeyAndKeyHandles(t, nil /*=kid*/, tinkpb.OutputPrefixType_TINK)
	signer, err := jwt.NewSigner(privateHandle)
	if err != nil {
		t.Fatalf("jwt.NewSigner() err = %v, want nil", err)
	}
	verifier, err := jwt.NewVerifier(publicHandle)
	if err != nil {
		t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
	}

	audience := "audience"
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{Audience: &audience, WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}

	compact, err := signer.SignAndEncode(rawJWT)
	if err != nil {
		t.Errorf("signer.SignAndEncode() err = %v, want nil", err)
	}

	otherAudience := "otherAudience"
	validator, err := jwt.NewValidator(
		&jwt.ValidatorOpts{ExpectedAudience: &otherAudience, AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	_, err = verifier.VerifyAndDecode(compact, validator)
	wantErr := "validating audience claim: otherAudience not found"
	if err == nil {
		t.Errorf("verifier.VerifyAndDecode() err = nil, want %q", wantErr)
	}
	if err.Error() != wantErr {
		t.Errorf("verifier.VerifyAndDecode() err = %q, want %q", err.Error(), wantErr)
	}
}

func TestFactorySignVerifyWithKIDSuccess(t *testing.T) {
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	for _, tc := range []signerVerifierFactoryKIDTestCase{
		{
			tag:                "signer verifier without custom kid and with raw output prefix",
			signerOutputPrefix: tinkpb.OutputPrefixType_RAW,
			signerKID:          nil,

			verifierOutputPrefix: tinkpb.OutputPrefixType_RAW,
			verifierKID:          nil,
		},
		{
			tag:                  "signer with custom kid verifier without custom kid and raw output prefixes",
			signerOutputPrefix:   tinkpb.OutputPrefixType_RAW,
			signerKID:            refString("customKID"),
			verifierOutputPrefix: tinkpb.OutputPrefixType_RAW,
			verifierKID:          nil,
		},
		{
			tag:                  "signer and verifier same custom kid and raw output prefix",
			signerOutputPrefix:   tinkpb.OutputPrefixType_RAW,
			signerKID:            refString("customKID"),
			verifierOutputPrefix: tinkpb.OutputPrefixType_RAW,
			verifierKID:          refString("customKID"),
		},
		{
			tag:                  "signer and verifier with tink output prefix and no custom kid",
			signerOutputPrefix:   tinkpb.OutputPrefixType_TINK,
			signerKID:            nil,
			verifierOutputPrefix: tinkpb.OutputPrefixType_TINK,
			verifierKID:          nil,
		},
		{
			tag:                  "signer with tink output prefix verifier with raw output prefix",
			signerOutputPrefix:   tinkpb.OutputPrefixType_TINK,
			signerKID:            nil,
			verifierOutputPrefix: tinkpb.OutputPrefixType_RAW,
			verifierKID:          nil,
		},
		{
			tag:                  "token missing kid in header when verifier has custom kid",
			signerOutputPrefix:   tinkpb.OutputPrefixType_RAW,
			signerKID:            nil,
			verifierOutputPrefix: tinkpb.OutputPrefixType_RAW,
			verifierKID:          refString("customKID"),
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			key, privKeyHandle, _ := createKeyAndKeyHandles(t, tc.signerKID, tc.signerOutputPrefix)
			signer, err := jwt.NewSigner(privKeyHandle)
			if err != nil {
				t.Fatalf("jwt.NewSigner() err = %v, want nil", err)
			}
			compact, err := signer.SignAndEncode(rawJWT)
			if err != nil {
				t.Errorf("signer.SignAndEncode() err = %v, want nil", err)
			}

			key.GetPublicKey().CustomKid = nil
			if tc.verifierKID != nil {
				key.GetPublicKey().CustomKid = &jepb.JwtEcdsaPublicKey_CustomKid{Value: *tc.verifierKID}
			}
			_, pubKeyHandle := createKeyHandlesFromKey(t, key, tc.verifierOutputPrefix)
			verifier, err := jwt.NewVerifier(pubKeyHandle)
			if err != nil {
				t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
			}
			if _, err := verifier.VerifyAndDecode(compact, validator); err != nil {
				t.Errorf("verifier.VerifyAndDecode() err = %v, want nil", err)
			}
		})
	}
}

func TestFactorySignVerifyWithoutAnnotationsEmitsNoMonitoring(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	privHandle, err := keyset.NewHandle(jwt.ES256Template())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	pubHandle, err := privHandle.Public()
	if err != nil {
		t.Fatalf("privHandle.Public() err = %v, want nil", err)
	}
	signer, err := jwt.NewSigner(privHandle)
	if err != nil {
		t.Fatalf("jwt.NewSigner() err = %v, want nil", err)
	}
	verifier, err := jwt.NewVerifier(pubHandle)
	if err != nil {
		t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
	}
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	compact, err := signer.SignAndEncode(rawJWT)
	if err != nil {
		t.Fatalf("signer.SignAndEncode() err = %v, want nil", err)
	}
	if _, err := verifier.VerifyAndDecode(compact, validator); err != nil {
		t.Fatalf("verifier.VerifyAndDecode() err = %v, want nil", err)
	}
	if len(client.Events()) != 0 {
		t.Errorf("len(client.Events()) = %d, want 0", len(client.Events()))
	}
	if len(client.Failures()) != 0 {
		t.Errorf("len(client.Failures()) = %d, want 0", len(client.Failures()))
	}
}

func TestFactorySignWithAnnotationsEmitsMonitoringSuccess(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	handle, err := keyset.NewHandle(jwt.ES256Template())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	privHandle, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	// Verify annotations aren't propagated.
	pubHandle, err := privHandle.Public()
	if err != nil {
		t.Fatalf("privHandle.Public() err = %v, want nil", err)
	}
	signer, err := jwt.NewSigner(privHandle)
	if err != nil {
		t.Fatalf("jwt.NewSigner() err = %v, want nil", err)
	}
	verifier, err := jwt.NewVerifier(pubHandle)
	if err != nil {
		t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
	}
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	compact, err := signer.SignAndEncode(rawJWT)
	if err != nil {
		t.Fatalf("signer.SignAndEncode() err = %v, want nil", err)
	}
	if _, err := verifier.VerifyAndDecode(compact, validator); err != nil {
		t.Fatalf("verifier.VerifyAndDecode() err = %v, want nil", err)
	}
	// verify error emits no monitoring.
	if _, err := verifier.VerifyAndDecode("invalid", validator); err == nil {
		t.Fatalf("verifier.VerifyAndDecode() err = %v, want nil", err)
	}
	if len(client.Failures()) != 0 {
		t.Errorf("len(client.Failures()) = %d, want 0", len(client.Failures()))
	}
	if len(client.Events()) != 1 {
		t.Errorf("len(client.Events()) = %d, want 1", len(client.Events()))
	}
	got := client.Events()
	wantSignKeysetInfo := &monitoring.KeysetInfo{
		Annotations:  annotations,
		PrimaryKeyID: privHandle.KeysetInfo().GetPrimaryKeyId(),
		Entries: []*monitoring.Entry{
			{
				KeyID:     privHandle.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.JwtEcdsaPrivateKey",
				KeyPrefix: "TINK",
			},
		},
	}
	want := []*fakemonitoring.LogEvent{
		{
			Context:  monitoring.NewContext("jwtsign", "sign", wantSignKeysetInfo),
			KeyID:    privHandle.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: 1,
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("%v", diff)
	}
}

func TestFactoryVerifyWithAnnotationsEmitsMonitoringSuccess(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	privHandle, err := keyset.NewHandle(jwt.ES256Template())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	signer, err := jwt.NewSigner(privHandle)
	if err != nil {
		t.Fatalf("jwt.NewSigner() err = %v, want nil", err)
	}

	pubHandle, err := privHandle.Public()
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(pubHandle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	pubHandle, err = insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	verifier, err := jwt.NewVerifier(pubHandle)
	if err != nil {
		t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
	}
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	compact, err := signer.SignAndEncode(rawJWT)
	if err != nil {
		t.Fatalf("signer.SignAndEncode() err = %v, want nil", err)
	}
	if _, err := verifier.VerifyAndDecode(compact, validator); err != nil {
		t.Fatalf("verifier.VerifyAndDecode() err = %v, want nil", err)
	}
	if len(client.Failures()) != 0 {
		t.Errorf("len(client.Failures()) = %d, want 0", len(client.Failures()))
	}
	if len(client.Events()) != 1 {
		t.Errorf("len(client.Events()) = %d, want 1", len(client.Events()))
	}
	got := client.Events()
	wantSignKeysetInfo := &monitoring.KeysetInfo{
		Annotations:  annotations,
		PrimaryKeyID: privHandle.KeysetInfo().GetPrimaryKeyId(),
		Entries: []*monitoring.Entry{
			{
				KeyID:     privHandle.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.JwtEcdsaPublicKey",
				KeyPrefix: "TINK",
			},
		},
	}
	want := []*fakemonitoring.LogEvent{
		{
			Context:  monitoring.NewContext("jwtverify", "verify", wantSignKeysetInfo),
			KeyID:    privHandle.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: 1,
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("%v", diff)
	}
}

func TestFactorySignAndVerifyWithAnnotationsEmitsMonitoringOnError(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	// Create valid keyset handles.
	_, privHandle, pubHandle := createKeyAndKeyHandles(t, nil, tinkpb.OutputPrefixType_TINK)
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(privHandle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	privHandle, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	signer, err := jwt.NewSigner(privHandle)
	if err != nil {
		t.Fatalf("jwt.NewSigner() err = %v, want nil", err)
	}
	buff.Reset()
	if err := insecurecleartextkeyset.Write(pubHandle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	pubHandle, err = insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	verifier, err := jwt.NewVerifier(pubHandle)
	if err != nil {
		t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	// Fails because of nil rawJWT.
	if _, err := signer.SignAndEncode(nil); err == nil {
		t.Fatalf("signer.SignAndEncode() err = nil, want error")
	}
	// Fails because of invalid token.
	if _, err := verifier.VerifyAndDecode("invalid_token", validator); err == nil {
		t.Fatalf("verifier.VerifyAndDecode() err = nil want error")
	}
	if len(client.Failures()) != 2 {
		t.Errorf("len(client.Failures()) = %d, want 2", len(client.Failures()))
	}
}

const stubPrivateKeyURL = "type.googleapis.com/google.crypto.tink.StubPrivateKey"
const stubPublicKeyURL = "type.googleapis.com/google.crypto.tink.StubPublicKey"

type stubFullSigner struct {
	kid *string
}

var _ jwt.Signer = (*stubFullSigner)(nil)

func (s *stubFullSigner) SignAndEncode(_ *jwt.RawJWT) (string, error) {
	if s.kid == nil {
		return "full_signer", nil
	}
	return *s.kid + "_full_signer", nil
}

type stubFullVerifier struct{}

var _ jwt.Verifier = (*stubFullVerifier)(nil)

func (s *stubFullVerifier) VerifyAndDecode(t string, _ *jwt.Validator) (*jwt.VerifiedJWT, error) {
	if t != "AQIDBA_full_signer" {
		return nil, fmt.Errorf("invalid token")
	}
	return &jwt.VerifiedJWT{}, nil
}

// Parameters and keys.

type stubParams struct{}

var _ key.Parameters = (*stubParams)(nil)

func (p *stubParams) Equal(_ key.Parameters) bool { return true }
func (p *stubParams) HasIDRequirement() bool      { return true }

type stubPublicKey struct {
	prefixType    tinkpb.OutputPrefixType
	idRequirement uint32
}

var _ key.Key = (*stubPublicKey)(nil)

func (p *stubPublicKey) Equal(_ key.Key) bool          { return true }
func (p *stubPublicKey) Parameters() key.Parameters    { return &stubParams{} }
func (p *stubPublicKey) IDRequirement() (uint32, bool) { return p.idRequirement, p.HasIDRequirement() }
func (p *stubPublicKey) HasIDRequirement() bool        { return p.prefixType == tinkpb.OutputPrefixType_RAW }

type stubPrivateKey struct {
	prefixType    tinkpb.OutputPrefixType
	idRequirement uint32
}

var _ key.Key = (*stubPrivateKey)(nil)

func (p *stubPrivateKey) Equal(_ key.Key) bool          { return true }
func (p *stubPrivateKey) Parameters() key.Parameters    { return &stubParams{} }
func (p *stubPrivateKey) IDRequirement() (uint32, bool) { return p.idRequirement, p.HasIDRequirement() }
func (p *stubPrivateKey) HasIDRequirement() bool        { return p.prefixType != tinkpb.OutputPrefixType_RAW }
func (p *stubPrivateKey) PublicKey() (key.Key, error) {
	return &stubPublicKey{
		prefixType:    p.prefixType,
		idRequirement: p.idRequirement,
	}, nil
}

// Proto serialization.

type stubPublicKeySerialization struct{}

var _ protoserialization.KeySerializer = (*stubPublicKeySerialization)(nil)

func (s *stubPublicKeySerialization) SerializeKey(key key.Key) (*protoserialization.KeySerialization, error) {
	return protoserialization.NewKeySerialization(
		&tinkpb.KeyData{
			TypeUrl:         stubPublicKeyURL,
			Value:           []byte("serialized_public_key"),
			KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
		},
		key.(*stubPublicKey).prefixType,
		key.(*stubPublicKey).idRequirement,
	)
}

type stubPublicKeyParser struct{}

var _ protoserialization.KeyParser = (*stubPublicKeyParser)(nil)

func (s *stubPublicKeyParser) ParseKey(serialization *protoserialization.KeySerialization) (key.Key, error) {
	idRequirement, _ := serialization.IDRequirement()
	return &stubPublicKey{
		prefixType:    serialization.OutputPrefixType(),
		idRequirement: idRequirement,
	}, nil
}

type stubPrivateKeySerialization struct{}

var _ protoserialization.KeySerializer = (*stubPrivateKeySerialization)(nil)

func (s *stubPrivateKeySerialization) SerializeKey(key key.Key) (*protoserialization.KeySerialization, error) {
	return protoserialization.NewKeySerialization(
		&tinkpb.KeyData{
			TypeUrl:         stubPrivateKeyURL,
			Value:           []byte("serialized_key"),
			KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
		},
		key.(*stubPrivateKey).prefixType,
		key.(*stubPrivateKey).idRequirement,
	)
}

type stubPrivateKeyParser struct{}

var _ protoserialization.KeyParser = (*stubPrivateKeyParser)(nil)

func (s *stubPrivateKeyParser) ParseKey(serialization *protoserialization.KeySerialization) (key.Key, error) {
	idRequirement, _ := serialization.IDRequirement()
	return &stubPrivateKey{
		prefixType:    serialization.OutputPrefixType(),
		idRequirement: idRequirement,
	}, nil
}

func TestPrimitiveFactoryUsesFullPrimitiveIfRegistered(t *testing.T) {
	defer protoserialization.UnregisterKeyParser(stubPublicKeyURL)
	defer protoserialization.UnregisterKeyParser(stubPrivateKeyURL)
	defer protoserialization.UnregisterKeySerializer[*stubPrivateKey]()
	defer protoserialization.UnregisterKeySerializer[*stubPublicKey]()

	if err := protoserialization.RegisterKeyParser(stubPublicKeyURL, &stubPublicKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeySerializer[*stubPublicKey](&stubPublicKeySerialization{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeyParser(stubPrivateKeyURL, &stubPrivateKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeySerializer[*stubPrivateKey](&stubPrivateKeySerialization{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v, want nil", err)
	}

	// Register primitive constructors to make sure that the factory uses full
	// primitives.
	defer primitiveregistry.UnregisterPrimitiveConstructor[*stubPrivateKey]()
	defer primitiveregistry.UnregisterPrimitiveConstructor[*stubPublicKey]()

	signerConstructor := func(key key.Key) (any, error) {
		kid := "AQIDBA" // for 0x01020304
		return &stubFullSigner{&kid}, nil
	}
	if err := primitiveregistry.RegisterPrimitiveConstructor[*stubPrivateKey](signerConstructor); err != nil {
		t.Fatalf("primitiveregistry.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	verifierConstructor := func(key key.Key) (any, error) { return &stubFullVerifier{}, nil }
	if err := primitiveregistry.RegisterPrimitiveConstructor[*stubPublicKey](verifierConstructor); err != nil {
		t.Fatalf("primitiveregistry.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}

	km := keyset.NewManager()
	keyID, err := km.AddKey(&stubPrivateKey{
		prefixType:    tinkpb.OutputPrefixType_TINK,
		idRequirement: 0x01020304,
	})
	if err != nil {
		t.Fatalf("km.AddKey() err = %v, want nil", err)
	}
	if err := km.SetPrimary(keyID); err != nil {
		t.Fatalf("km.SetPrimary() err = %v, want nil", err)
	}
	handle, err := km.Handle()
	if err != nil {
		t.Fatalf("km.Handle() err = %v, want nil", err)
	}

	signer, err := jwt.NewSigner(handle)
	if err != nil {
		t.Fatalf("jwt.NewSigner() err = %v, want nil", err)
	}
	data, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	token, err := signer.SignAndEncode(data)
	if err != nil {
		t.Fatalf("signer.SignAndEncode(() err = %v, want nil", err)
	}
	if !cmp.Equal(token, "AQIDBA_full_signer") {
		t.Errorf("token = %q, want: %q", token, "full_primitive")
	}

	publicHandle, err := handle.Public()
	if err != nil {
		t.Fatalf("handle.Public() err = %v, want nil", err)
	}
	verifier, err := jwt.NewVerifier(publicHandle)
	if err != nil {
		t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	if _, err := verifier.VerifyAndDecode(token, validator); err != nil {
		t.Fatalf("verifier.VerifyAndDecode() err = %v, want nil", err)
	}
}

type stubLegacySigner struct{}

func (s *stubLegacySigner) SignAndEncodeWithKID(_ *jwt.RawJWT, kid *string) (string, error) {
	if kid == nil {
		return "legacy_signer", nil
	}
	return *kid + "_legacy_signer", nil
}

type stubLegacyVerifier struct{}

func (s *stubLegacyVerifier) VerifyAndDecodeWithKID(compact string, _ *jwt.Validator, kid *string) (*jwt.VerifiedJWT, error) {
	if kid == nil {
		if compact == "legacy_signer" {
			return &jwt.VerifiedJWT{}, nil
		}
	} else {
		if compact == *kid+"_legacy_signer" {
			return &jwt.VerifiedJWT{}, nil
		}
	}
	return nil, fmt.Errorf("invalid token")
}

type stubPrivateKeyManager struct{}

var _ registry.KeyManager = (*stubPrivateKeyManager)(nil)

func (km *stubPrivateKeyManager) NewKey(_ []byte) (proto.Message, error) {
	return nil, fmt.Errorf("not implemented")
}
func (km *stubPrivateKeyManager) NewKeyData(_ []byte) (*tinkpb.KeyData, error) {
	return nil, fmt.Errorf("not implemented")
}
func (km *stubPrivateKeyManager) DoesSupport(keyURL string) bool {
	return keyURL == stubPrivateKeyURL
}
func (km *stubPrivateKeyManager) TypeURL() string { return stubPrivateKeyURL }
func (km *stubPrivateKeyManager) Primitive(_ []byte) (any, error) {
	return &stubLegacySigner{}, nil
}

type stubPublicKeyManager struct{}

var _ registry.KeyManager = (*stubPublicKeyManager)(nil)

func (km *stubPublicKeyManager) NewKey(_ []byte) (proto.Message, error) {
	return nil, fmt.Errorf("not implemented")
}
func (km *stubPublicKeyManager) NewKeyData(_ []byte) (*tinkpb.KeyData, error) {
	return nil, fmt.Errorf("not implemented")
}
func (km *stubPublicKeyManager) DoesSupport(keyURL string) bool {
	return keyURL == stubPublicKeyURL
}
func (km *stubPublicKeyManager) TypeURL() string { return stubPublicKeyURL }
func (km *stubPublicKeyManager) Primitive(_ []byte) (any, error) {
	return &stubLegacyVerifier{}, nil
}

func TestPrimitiveFactoryUsesLegacyPrimitive(t *testing.T) {
	defer protoserialization.UnregisterKeyParser(stubPublicKeyURL)
	defer protoserialization.UnregisterKeyParser(stubPrivateKeyURL)
	defer protoserialization.UnregisterKeySerializer[*stubPrivateKey]()
	defer protoserialization.UnregisterKeySerializer[*stubPublicKey]()

	if err := protoserialization.RegisterKeyParser(stubPublicKeyURL, &stubPublicKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeySerializer[*stubPublicKey](&stubPublicKeySerialization{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeyParser(stubPrivateKeyURL, &stubPrivateKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeySerializer[*stubPrivateKey](&stubPrivateKeySerialization{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v, want nil", err)
	}

	defer registry.UnregisterKeyManager(stubPrivateKeyURL, internalapi.Token{})
	defer registry.UnregisterKeyManager(stubPublicKeyURL, internalapi.Token{})

	if err := registry.RegisterKeyManager(&stubPrivateKeyManager{}); err != nil {
		t.Fatalf("registry.RegisterKeyManager() err = %v, want nil", err)
	}
	if err := registry.RegisterKeyManager(&stubPublicKeyManager{}); err != nil {
		t.Fatalf("registry.RegisterKeyManager() err = %v, want nil", err)
	}

	for _, tc := range []struct {
		name      string
		key       *stubPrivateKey
		wantToken string
	}{
		{
			name:      "TINK",
			key:       &stubPrivateKey{tinkpb.OutputPrefixType_TINK, 0x01020304},
			wantToken: "AQIDBA_legacy_signer",
		},
		{
			name:      "RAW",
			key:       &stubPrivateKey{tinkpb.OutputPrefixType_RAW, 0},
			wantToken: "legacy_signer",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Create a keyset with a single key.
			km := keyset.NewManager()
			keyID, err := km.AddKey(tc.key)
			if err != nil {
				t.Fatalf("km.AddKey() err = %v, want nil", err)
			}
			if err := km.SetPrimary(keyID); err != nil {
				t.Fatalf("km.SetPrimary() err = %v, want nil", err)
			}
			handle, err := km.Handle()
			if err != nil {
				t.Fatalf("km.Handle() err = %v, want nil", err)
			}

			signer, err := jwt.NewSigner(handle)
			if err != nil {
				t.Fatalf("jwt.NewSigner() err = %v, want nil", err)
			}
			data, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
			if err != nil {
				t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
			}

			token, err := signer.SignAndEncode(data)
			if err != nil {
				t.Fatalf("signer.SignAndEncode(() err = %v, want nil", err)
			}
			if !cmp.Equal(token, tc.wantToken) {
				t.Errorf("token = %q, want: %q", token, tc.wantToken)
			}

			publicHandle, err := handle.Public()
			if err != nil {
				t.Fatalf("handle.Public() err = %v, want nil", err)
			}
			verifier, err := jwt.NewVerifier(publicHandle)
			if err != nil {
				t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
			}
			validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
			if err != nil {
				t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
			}
			if _, err := verifier.VerifyAndDecode(token, validator); err != nil {
				t.Fatalf("verifier.VerifyAndDecode() err = %v, want nil", err)
			}
		})
	}
}

// TestPrimitiveFactoryMultipleKeys tests that the factory can create a signer
// and a verifier from a keyset with all JWT signer keys.
func TestPrimitiveFactoryMultipleKeys(t *testing.T) {
	km := keyset.NewManager()
	keyID, err := km.Add(jwt.ES256Template())
	if err != nil {
		t.Fatalf("km.Add() err = %v, want nil", err)
	}
	if err := km.SetPrimary(keyID); err != nil {
		t.Fatalf("km.SetPrimary() err = %v, want nil", err)
	}
	if _, err := km.Add(jwt.RS256_2048_F4_Key_Template()); err != nil {
		t.Fatalf("km.Add() err = %v, want nil", err)
	}
	if _, err := km.Add(jwt.RS256_2048_F4_Key_Template()); err != nil {
		t.Fatalf("km.Add() err = %v, want nil", err)
	}
	if _, err := km.Add(jwt.PS256_2048_F4_Key_Template()); err != nil {
		t.Fatalf("km.Add() err = %v, want nil", err)
	}
	handle, err := km.Handle()
	if err != nil {
		t.Fatalf("km.Handle() err = %v, want nil", err)
	}
	if _, err := jwt.NewSigner(handle); err != nil {
		t.Fatalf("jwt.NewSigner() err = %v, want nil", err)
	}
	publicHandle, err := handle.Public()
	if err != nil {
		t.Fatalf("handle.Public() err = %v, want nil", err)
	}
	if _, err := jwt.NewVerifier(publicHandle); err != nil {
		t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
	}
}
