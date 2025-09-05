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
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/testing/fakemonitoring"
	"github.com/tink-crypto/tink-go/v2/testkeyset"
	"github.com/tink-crypto/tink-go/v2/testutil"

	jwtmacpb "github.com/tink-crypto/tink-go/v2/proto/jwt_hmac_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	stubKeyTypeURL = "type.googleapis.com/google.crypto.tink.StubKey"
)

func newJWTHMACKey(algorithm jwtmacpb.JwtHmacAlgorithm, kid *jwtmacpb.JwtHmacKey_CustomKid) *jwtmacpb.JwtHmacKey {
	return &jwtmacpb.JwtHmacKey{
		Version:   0,
		Algorithm: algorithm,
		KeyValue:  random.GetRandomBytes(32),
		CustomKid: kid,
	}
}

func newKeyData(key *jwtmacpb.JwtHmacKey) (*tinkpb.KeyData, error) {
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         "type.googleapis.com/google.crypto.tink.JwtHmacKey",
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, nil
}

func createJWTMAC(keyData *tinkpb.KeyData, prefixType tinkpb.OutputPrefixType) (jwt.MAC, error) {
	primaryKey := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 42, prefixType)
	handle, err := testkeyset.NewHandle(testutil.NewKeyset(primaryKey.KeyId, []*tinkpb.Keyset_Key{primaryKey}))
	if err != nil {
		return nil, fmt.Errorf("creating keyset handle: %v", err)
	}
	return jwt.NewMAC(handle)
}

func verifyMACCompareSubject(p jwt.MAC, compact string, validator *jwt.Validator, wantSubject string) error {
	verifiedJWT, err := p.VerifyMACAndDecode(compact, validator)
	if err != nil {
		return fmt.Errorf("p.VerifyMACAndDecode() err = %v, want nil", err)
	}
	subject, err := verifiedJWT.Subject()
	if err != nil {
		return fmt.Errorf("verifiedJWT.Subject() err = %v, want nil", err)
	}
	if subject != wantSubject {
		return fmt.Errorf("verifiedJWT.Subject() = %q, want %q", subject, wantSubject)
	}
	return nil
}

func TestNilKeyHandle(t *testing.T) {
	if _, err := jwt.NewMAC(nil); err == nil {
		t.Errorf("TestNilKeyHandle(nil) err = nil, want error")
	}
}

func TestFactorySameKeyMaterialWithRawPrefixAndNoKIDShouldIgnoreHeader(t *testing.T) {
	keyData, err := newKeyData(newJWTHMACKey(jwtmacpb.JwtHmacAlgorithm_HS256, nil))
	if err != nil {
		t.Fatalf("creating NewKeyData: %v", err)
	}
	p, err := createJWTMAC(keyData, tinkpb.OutputPrefixType_TINK)
	if err != nil {
		t.Fatalf("creating New JWT MAC: %v", err)
	}

	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true, Subject: refString("tink-subject")})
	if err != nil {
		t.Errorf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Errorf("jwt.NewValidator() err = %v, want nil", err)
	}
	compact, err := p.ComputeMACAndEncode(rawJWT)
	if err != nil {
		t.Errorf("p.ComputeMACAndEncode() err = %v, want nil", err)
	}
	if err := verifyMACCompareSubject(p, compact, validator, "tink-subject"); err != nil {
		t.Error(err)
	}
	p, err = createJWTMAC(keyData, tinkpb.OutputPrefixType_RAW)
	if err != nil {
		t.Fatalf("creating New JWT MAC: %v", err)
	}
	if _, err := p.VerifyMACAndDecode(compact, validator); err != nil {
		t.Errorf("VerifyMACAndDecode() with a RAW key err = %v, want nil", err)
	}
}

func TestFactorySameKeyMaterialWithDifferentPrefixAndKIDShouldFailVerification(t *testing.T) {
	key := newJWTHMACKey(jwtmacpb.JwtHmacAlgorithm_HS256, nil)
	keyData, err := newKeyData(key)
	if err != nil {
		t.Fatalf("creating NewKeyData: %v", err)
	}
	p, err := createJWTMAC(keyData, tinkpb.OutputPrefixType_TINK)
	if err != nil {
		t.Fatalf("creating New JWT MAC: %v", err)
	}

	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true, Subject: refString("tink-subject")})
	if err != nil {
		t.Errorf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Errorf("jwt.NewValidator() err = %v, want nil", err)
	}
	compact, err := p.ComputeMACAndEncode(rawJWT)
	if err != nil {
		t.Errorf("p.ComputeMACAndEncode() err = %v, want nil", err)
	}
	if err := verifyMACCompareSubject(p, compact, validator, "tink-subject"); err != nil {
		t.Error(err)
	}
	key.CustomKid = &jwtmacpb.JwtHmacKey_CustomKid{
		Value: "custom-kid",
	}
	rawKeyData, err := newKeyData(key)
	if err != nil {
		t.Fatalf("creating NewKeyData: %v", err)
	}
	p, err = createJWTMAC(rawKeyData, tinkpb.OutputPrefixType_RAW)
	if err != nil {
		t.Fatalf("creating New JWT MAC: %v", err)
	}
	if _, err := p.VerifyMACAndDecode(compact, validator); err == nil {
		t.Errorf("VerifyMACAndDecode() with a different KID = nil, want error")
	}
}

func TestFactoryDifferentKeyShouldFailValidation(t *testing.T) {
	keyData, err := newKeyData(newJWTHMACKey(jwtmacpb.JwtHmacAlgorithm_HS256, nil))
	if err != nil {
		t.Fatalf("creating NewKeyData: %v", err)
	}
	p, err := createJWTMAC(keyData, tinkpb.OutputPrefixType_TINK)
	if err != nil {
		t.Fatalf("creating New JWT MAC: %v", err)
	}

	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true, Subject: refString("tink-subject")})
	if err != nil {
		t.Errorf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Errorf("jwt.NewValidator() err = %v, want nil", err)
	}
	compact, err := p.ComputeMACAndEncode(rawJWT)
	if err != nil {
		t.Errorf("p.ComputeMACAndEncode() err = %v, want nil", err)
	}
	if err := verifyMACCompareSubject(p, compact, validator, "tink-subject"); err != nil {
		t.Error(err)
	}
	diffKey := newJWTHMACKey(jwtmacpb.JwtHmacAlgorithm_HS256, nil)
	diffKeyData, err := newKeyData(diffKey)
	if err != nil {
		t.Fatalf("creating NewKeyData: %v", err)
	}
	p, err = createJWTMAC(diffKeyData, tinkpb.OutputPrefixType_TINK)
	if err != nil {
		t.Fatalf("creating New JWT MAC: %v", err)
	}
	if _, err := p.VerifyMACAndDecode(compact, validator); err == nil {
		t.Errorf("VerifyMACAndDecode() with a different key = nil, want error")
	}
}

func TestFactoryWithRAWKeyAndKID(t *testing.T) {
	key := newJWTHMACKey(jwtmacpb.JwtHmacAlgorithm_HS256, &jwtmacpb.JwtHmacKey_CustomKid{Value: "custom-123"})
	keyData, err := newKeyData(key)
	if err != nil {
		t.Fatalf("creating NewKeyData: %v", err)
	}
	primaryKey := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 42, tinkpb.OutputPrefixType_RAW)
	ks := testutil.NewKeyset(primaryKey.KeyId, []*tinkpb.Keyset_Key{primaryKey})

	handle, err := testkeyset.NewHandle(ks)
	if err != nil {
		t.Fatalf("creating keyset handle: %v", err)
	}
	p, err := jwt.NewMAC(handle)
	if err != nil {
		t.Fatalf("creating New JWT MAC: %v", err)
	}
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true, Subject: refString("tink-subject")})
	if err != nil {
		t.Errorf("NewRawJWT() err = %v, want nil", err)
	}

	compact, err := p.ComputeMACAndEncode(rawJWT)
	if err != nil {
		t.Errorf("p.ComputeMACAndEncode() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Errorf("NewValidator() err = %v, want nil", err)
	}
	if _, err := p.VerifyMACAndDecode(compact, validator); err != nil {
		t.Errorf("p.VerifyMACAndDecode() err = %v, want nil", err)
	}
}

func TestFactoryWithInvalidPrimitiveSetType(t *testing.T) {
	kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("failed to build *keyset.Handle: %s", err)
	}
	if _, err = jwt.NewMAC(kh); err == nil {
		t.Fatal("calling NewMAC() err = nil, want error")
	}
}

func TestVerifyMACAndDecodeReturnsValidationError(t *testing.T) {
	keyData, err := newKeyData(newJWTHMACKey(jwtmacpb.JwtHmacAlgorithm_HS256, nil))
	if err != nil {
		t.Fatalf("creating NewKeyData: %v", err)
	}
	p, err := createJWTMAC(keyData, tinkpb.OutputPrefixType_TINK)
	if err != nil {
		t.Fatalf("creating New JWT MAC: %v", err)
	}

	audience := "audience"
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{Audience: &audience, WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	token, err := p.ComputeMACAndEncode(rawJWT)
	if err != nil {
		t.Errorf("p.ComputeMACAndEncode() err = %v, want nil", err)
	}

	otherAudience := "otherAudience"
	validator, err := jwt.NewValidator(
		&jwt.ValidatorOpts{ExpectedAudience: &otherAudience, AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}

	_, err = p.VerifyMACAndDecode(token, validator)
	wantErr := "validating audience claim: otherAudience not found"
	if err == nil {
		t.Errorf("p.VerifyMACAndDecode() err = nil, want %q", wantErr)
	}
	if err.Error() != wantErr {
		t.Errorf("p.VerifyMACAndDecode() err = %q, want %q", err.Error(), wantErr)
	}
}

func TestComputeAndVerifyWithoutAnnotationsEmitsNoMonitoring(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	kh, err := keyset.NewHandle(jwt.HS256Template())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	p, err := jwt.NewMAC(kh)
	if err != nil {
		t.Fatalf("jwt.NewMAC() err = %v, want nil", err)
	}
	audience := "audience"
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{Audience: &audience, WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	token, err := p.ComputeMACAndEncode(rawJWT)
	if err != nil {
		t.Errorf("p.ComputeMACAndEncode() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(
		&jwt.ValidatorOpts{ExpectedAudience: &audience, AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	if _, err = p.VerifyMACAndDecode(token, validator); err != nil {
		t.Errorf("p.VerifyMACAndDecode() err = %v, want error", err)
	}
	if len(client.Failures()) != 0 {
		t.Errorf("len(client.Failures()) = %d, want = 0", len(client.Failures()))
	}
	if len(client.Events()) != 0 {
		t.Errorf("len(client.Events()) = %d, want = 0", len(client.Events()))
	}
}

// Defines a stub JWT MAC full primitive to test the factory.
type stubFullMAC struct {
	kid *string
}

func (s *stubFullMAC) ComputeMACAndEncode(_ *jwt.RawJWT) (string, error) {
	if s.kid == nil {
		return "stub_full_mac", nil
	}
	return *s.kid + "_stub_full_mac", nil
}

func (s *stubFullMAC) VerifyMACAndDecode(compact string, _ *jwt.Validator) (*jwt.VerifiedJWT, error) {
	if compact != "AQIDBA_stub_full_mac" {
		return nil, fmt.Errorf("invalid token")
	}
	return &jwt.VerifiedJWT{}, nil
}

// Defines a stub key for the stub JWT MAC full primitive.
type stubKey struct {
	idRequirement uint32
	prefixType    tinkpb.OutputPrefixType
}

func (s *stubKey) Parameters() key.Parameters { return nil }
func (s *stubKey) Equal(_ key.Key) bool       { return false }
func (s *stubKey) IDRequirement() (uint32, bool) {
	return s.idRequirement, s.prefixType != tinkpb.OutputPrefixType_RAW
}

// Defines a stub key parser for the stub JWT MAC full primitive.
type stubKeyParser struct{}

func (s *stubKeyParser) ParseKey(keySerialization *protoserialization.KeySerialization) (key.Key, error) {
	idRequirement, _ := keySerialization.IDRequirement()
	return &stubKey{
		idRequirement: idRequirement,
		prefixType:    keySerialization.OutputPrefixType(),
	}, nil
}

// Defines a stub key serializer for the stub JWT MAC full primitive.
type stubKeySerializer struct{}

func (s *stubKeySerializer) SerializeKey(k key.Key) (*protoserialization.KeySerialization, error) {
	stubk, ok := k.(*stubKey)
	if !ok {
		return nil, fmt.Errorf("invalid key type")
	}
	return protoserialization.NewKeySerialization(
		&tinkpb.KeyData{
			TypeUrl:         stubKeyTypeURL,
			Value:           []byte("stub_key"),
			KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
		},
		stubk.prefixType,
		stubk.idRequirement,
	)
}

func TestMACPrimitiveFactoryUsesFullPrimitiveIfRegistered(t *testing.T) {
	defer protoserialization.UnregisterKeyParser(stubKeyTypeURL)
	defer protoserialization.UnregisterKeySerializer[*stubKey]()
	if err := protoserialization.RegisterKeyParser(stubKeyTypeURL, &stubKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeySerializer[*stubKey](&stubKeySerializer{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v, want nil", err)
	}

	// Register primitive constructor to make sure that the factory uses full primitives.
	defer primitiveregistry.UnregisterPrimitiveConstructor[*stubKey]()
	macConstructor := func(key key.Key) (any, error) {
		kid := "AQIDBA" // for 0x01020304
		return &stubFullMAC{&kid}, nil
	}
	if err := primitiveregistry.RegisterPrimitiveConstructor[*stubKey](macConstructor); err != nil {
		t.Fatalf("primitiveregistry.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}

	km := keyset.NewManager()
	keyID, err := km.AddKey(&stubKey{idRequirement: 0x01020304, prefixType: tinkpb.OutputPrefixType_TINK})
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

	mac, err := jwt.NewMAC(handle)
	if err != nil {
		t.Fatalf("jwt.NewMAC() err = %v, want nil", err)
	}
	data, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	token, err := mac.ComputeMACAndEncode(data)
	if err != nil {
		t.Fatalf("mac.ComputeMACAndEncode() err = %v, want nil", err)
	}
	if token != "AQIDBA_stub_full_mac" {
		t.Errorf("token = %q, want: %q", token, "AQIDBA_stub_full_mac")
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	if _, err := mac.VerifyMACAndDecode(token, validator); err != nil {
		t.Fatalf("mac.VerifyMACAndDecode() err = %v, want nil", err)
	}
}

type stubLegacyMAC struct{}

func (s *stubLegacyMAC) ComputeMACAndEncodeWithKID(_ *jwt.RawJWT, kid *string) (string, error) {
	if kid == nil {
		return "legacy_mac", nil
	}
	return *kid + "_legacy_mac", nil
}
func (s *stubLegacyMAC) VerifyMACAndDecodeWithKID(compact string, _ *jwt.Validator, kid *string) (*jwt.VerifiedJWT, error) {
	if kid == nil {
		if compact == "legacy_mac" {
			return &jwt.VerifiedJWT{}, nil
		}
	} else {
		if compact == *kid+"_legacy_mac" {
			return &jwt.VerifiedJWT{}, nil
		}
	}
	return nil, fmt.Errorf("invalid token")
}

type stubKeyManager struct{}

func (km *stubKeyManager) NewKey(_ []byte) (proto.Message, error) {
	return nil, fmt.Errorf("not implemented")
}
func (km *stubKeyManager) NewKeyData(_ []byte) (*tinkpb.KeyData, error) {
	return nil, fmt.Errorf("not implemented")
}
func (km *stubKeyManager) DoesSupport(keyURL string) bool  { return keyURL == stubKeyTypeURL }
func (km *stubKeyManager) TypeURL() string                 { return stubKeyTypeURL }
func (km *stubKeyManager) Primitive(_ []byte) (any, error) { return &stubLegacyMAC{}, nil }

func TestMACPrimitiveFactoryUsesLegacyPrimitive(t *testing.T) {
	defer protoserialization.UnregisterKeyParser(stubKeyTypeURL)
	defer protoserialization.UnregisterKeySerializer[*stubKey]()
	if err := protoserialization.RegisterKeyParser(stubKeyTypeURL, &stubKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeySerializer[*stubKey](&stubKeySerializer{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v, want nil", err)
	}

	defer registry.UnregisterKeyManager(stubKeyTypeURL, internalapi.Token{})
	if err := registry.RegisterKeyManager(&stubKeyManager{}); err != nil {
		t.Fatalf("registry.RegisterKeyManager() err = %v, want nil", err)
	}

	for _, tc := range []struct {
		name      string
		key       *stubKey
		wantToken string
	}{
		{
			name:      "TINK",
			key:       &stubKey{idRequirement: 0x01020304, prefixType: tinkpb.OutputPrefixType_TINK},
			wantToken: "AQIDBA_legacy_mac",
		},
		{
			name:      "RAW",
			key:       &stubKey{idRequirement: 0, prefixType: tinkpb.OutputPrefixType_RAW},
			wantToken: "legacy_mac",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
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

			mac, err := jwt.NewMAC(handle)
			if err != nil {
				t.Fatalf("jwt.NewMAC() err = %v, want nil", err)
			}
			data, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
			if err != nil {
				t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
			}
			token, err := mac.ComputeMACAndEncode(data)
			if err != nil {
				t.Fatalf("mac.ComputeMACAndEncode() err = %v, want nil", err)
			}
			if token != tc.wantToken {
				t.Errorf("token = %q, want: %q", token, tc.wantToken)
			}
			validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
			if err != nil {
				t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
			}
			if _, err := mac.VerifyMACAndDecode(token, validator); err != nil {
				t.Fatalf("mac.VerifyMACAndDecode() err = %v, want nil", err)
			}
		})
	}
}

func TestComputeAndVerifyWithAnnotationsEmitsMonitoring(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	kh, err := keyset.NewHandle(jwt.HS256Template())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	// Annotations are only supported through the `insecurecleartextkeyset` API.
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(kh, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	mh, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	p, err := jwt.NewMAC(mh)
	if err != nil {
		t.Fatalf("jwt.NewMAC() err = %v, want nil", err)
	}
	audience := "audience"
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{Audience: &audience, WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	token, err := p.ComputeMACAndEncode(rawJWT)
	if err != nil {
		t.Errorf("p.ComputeMACAndEncode() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(
		&jwt.ValidatorOpts{ExpectedAudience: &audience, AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	if _, err = p.VerifyMACAndDecode(token, validator); err != nil {
		t.Errorf("p.VerifyMACAndDecode() err = %v, want error", err)
	}
	failures := client.Failures()
	if len(failures) != 0 {
		t.Errorf("len(client.Failures()) = %d, want = 0", len(failures))
	}
	got := client.Events()
	wantKeysetInfo := monitoring.NewKeysetInfo(
		annotations,
		kh.KeysetInfo().GetPrimaryKeyId(),
		[]*monitoring.Entry{
			{
				KeyID:     kh.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.JwtHmacKey",
				KeyPrefix: "TINK",
			},
		},
	)
	want := []*fakemonitoring.LogEvent{
		{
			KeyID:    mh.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: 1,
			Context:  monitoring.NewContext("jwtmac", "compute", wantKeysetInfo),
		},
		{
			KeyID:    mh.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: 1,
			Context:  monitoring.NewContext("jwtmac", "verify", wantKeysetInfo),
		},
	}
	if cmp.Diff(got, want) != "" {
		t.Errorf("%v", cmp.Diff(got, want))
	}
}

type alwaysFailingStubMAC struct{}

func (s *alwaysFailingStubMAC) ComputeMACAndEncode(_ *jwt.RawJWT) (string, error) {
	return "", fmt.Errorf("always failing")
}

func (s *alwaysFailingStubMAC) VerifyMACAndDecode(compact string, _ *jwt.Validator) (*jwt.VerifiedJWT, error) {
	return nil, fmt.Errorf("always failing")
}

func TestComputeFailureEmitsMonitoring(t *testing.T) {
	defer protoserialization.UnregisterKeyParser(stubKeyTypeURL)
	defer protoserialization.UnregisterKeySerializer[*stubKey]()
	if err := protoserialization.RegisterKeyParser(stubKeyTypeURL, &stubKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeySerializer[*stubKey](&stubKeySerializer{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v, want nil", err)
	}

	// Register primitive constructor to make sure that the factory uses full primitives.
	defer primitiveregistry.UnregisterPrimitiveConstructor[*stubKey]()
	if err := primitiveregistry.RegisterPrimitiveConstructor[*stubKey](func(key key.Key) (any, error) {
		return &alwaysFailingStubMAC{}, nil
	}); err != nil {
		t.Fatalf("primitiveregistry.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	defer internalregistry.ClearMonitoringClient()
	client := &fakemonitoring.Client{Name: ""}
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}

	km := keyset.NewManager()
	keyID, err := km.AddKey(&stubKey{idRequirement: 0x01020304, prefixType: tinkpb.OutputPrefixType_TINK})
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
	// Annotations are only supported through the `insecurecleartextkeyset` API.
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	mh, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	p, err := jwt.NewMAC(mh)
	if err != nil {
		t.Fatalf("jwt.NewMAC() err = %v, want nil", err)
	}
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	if _, err := p.ComputeMACAndEncode(rawJWT); err == nil {
		t.Errorf("p.ComputeMACAndEncode() err = nil, want error")
	}
	failures := client.Failures()
	if len(failures) != 1 {
		t.Errorf("len(client.Failures()) = %d, want = 1", len(failures))
	}
	if len(client.Events()) != 0 {
		t.Errorf("len(client.Events()) = %d, want = 0", len(client.Events()))
	}
}

func TestVerifyFailureEmitsMonitoring(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	kh, err := keyset.NewHandle(jwt.HS256Template())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	// Annotations are only supported through the `insecurecleartextkeyset` API.
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(kh, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	mh, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	p, err := jwt.NewMAC(mh)
	if err != nil {
		t.Fatalf("jwt.NewMAC() err = %v, want nil", err)
	}
	audience := "audience"
	validator, err := jwt.NewValidator(
		&jwt.ValidatorOpts{ExpectedAudience: &audience, AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	if _, err := p.VerifyMACAndDecode("", validator); err == nil {
		t.Errorf("p.VerifyMACAndDecode() err = nil, want error")
	}
	failures := client.Failures()
	if len(failures) != 1 {
		t.Errorf("len(client.Failures()) = %d, want = 1", len(failures))
	}
	if len(client.Events()) != 0 {
		t.Errorf("len(client.Events()) = %d, want = 0", len(client.Events()))
	}
}
