// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/Lycense-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

package jwtrsassapkcs1

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"

	jwtrsapb "github.com/tink-crypto/tink-go/v2/proto/jwt_rsa_ssa_pkcs1_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	privateKeyTypeURL = "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey"
	publicKeyTypeURL  = "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey"
)

type parametersSerializer struct{}

var _ protoserialization.ParametersSerializer = (*parametersSerializer)(nil)

func algorithmToProto(a Algorithm) jwtrsapb.JwtRsaSsaPkcs1Algorithm {
	switch a {
	case RS256:
		return jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256
	case RS384:
		return jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS384
	case RS512:
		return jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS512
	}
	// Should never happen.
	return jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS_UNKNOWN
}

func algorithmFromProto(a jwtrsapb.JwtRsaSsaPkcs1Algorithm) Algorithm {
	switch a {
	case jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS256:
		return RS256
	case jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS384:
		return RS384
	case jwtrsapb.JwtRsaSsaPkcs1Algorithm_RS512:
		return RS512
	}
	return UnknownAlgorithm
}

func outputPrefixTypeFromKIDStrategy(s KIDStrategy) tinkpb.OutputPrefixType {
	switch s {
	case CustomKID, IgnoredKID:
		return tinkpb.OutputPrefixType_RAW
	case Base64EncodedKeyIDAsKID:
		return tinkpb.OutputPrefixType_TINK
	}
	// Should never happen.
	return tinkpb.OutputPrefixType_UNKNOWN_PREFIX
}

func kidStrategyFromOutputPrefixType(s tinkpb.OutputPrefixType, hasCustomKID bool) KIDStrategy {
	switch s {
	case tinkpb.OutputPrefixType_RAW:
		if hasCustomKID {
			return CustomKID
		}
		return IgnoredKID
	case tinkpb.OutputPrefixType_TINK:
		return Base64EncodedKeyIDAsKID
	}
	return UnknownKIDStrategy
}

func (s *parametersSerializer) Serialize(p key.Parameters) (*tinkpb.KeyTemplate, error) {
	if p == nil {
		return nil, fmt.Errorf("parameters can't be nil")
	}
	params, ok := p.(*Parameters)
	if !ok {
		return nil, fmt.Errorf("invalid parameters type: got %T, want %T", p, (*Parameters)(nil))
	}
	keyFormat := &jwtrsapb.JwtRsaSsaPkcs1KeyFormat{
		Algorithm:         algorithmToProto(params.Algorithm()),
		ModulusSizeInBits: uint32(params.ModulusSizeInBits()),
		PublicExponent:    []byte{0x01, 0x00, 0x01}, // F4
		Version:           0,
	}
	serializedKeyFormat, err := proto.Marshal(keyFormat)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key format: %v", err)
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          privateKeyTypeURL,
		Value:            serializedKeyFormat,
		OutputPrefixType: outputPrefixTypeFromKIDStrategy(params.kidStrategy),
	}, nil
}

type parametersParser struct{}

var _ protoserialization.ParametersParser = (*parametersParser)(nil)

func (s *parametersParser) Parse(kt *tinkpb.KeyTemplate) (key.Parameters, error) {
	if kt == nil {
		return nil, fmt.Errorf("key template can't be nil")
	}
	if kt.GetTypeUrl() != privateKeyTypeURL {
		return nil, fmt.Errorf("invalid type URL: got %q, want %q", kt.GetTypeUrl(), privateKeyTypeURL)
	}
	keyFormat := &jwtrsapb.JwtRsaSsaPkcs1KeyFormat{}
	if err := proto.Unmarshal(kt.GetValue(), keyFormat); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key format: %v", err)
	}
	if keyFormat.GetVersion() != 0 {
		return nil, fmt.Errorf("invalid version: got %d, want 0", keyFormat.GetVersion())
	}
	// Key format cannot specify a CustomKID.
	kidStrategy := kidStrategyFromOutputPrefixType(kt.GetOutputPrefixType(), false)
	return NewParameters(ParametersOpts{
		KidStrategy:       kidStrategy,
		Algorithm:         algorithmFromProto(keyFormat.GetAlgorithm()),
		ModulusSizeInBits: int(keyFormat.GetModulusSizeInBits()),
		PublicExponent:    f4,
	})
}
