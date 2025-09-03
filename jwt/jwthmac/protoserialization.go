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

package jwthmac

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"

	jwthmacpb "github.com/tink-crypto/tink-go/v2/proto/jwt_hmac_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

type parametersSerializer struct{}

var _ protoserialization.ParametersSerializer = (*parametersSerializer)(nil)

func algorithmToProto(a Algorithm) jwthmacpb.JwtHmacAlgorithm {
	switch a {
	case HS256:
		return jwthmacpb.JwtHmacAlgorithm_HS256
	case HS384:
		return jwthmacpb.JwtHmacAlgorithm_HS384
	case HS512:
		return jwthmacpb.JwtHmacAlgorithm_HS512
	}
	return jwthmacpb.JwtHmacAlgorithm_HS_UNKNOWN
}

func algorithmFromProto(a jwthmacpb.JwtHmacAlgorithm) (Algorithm, error) {
	switch a {
	case jwthmacpb.JwtHmacAlgorithm_HS256:
		return HS256, nil
	case jwthmacpb.JwtHmacAlgorithm_HS384:
		return HS384, nil
	case jwthmacpb.JwtHmacAlgorithm_HS512:
		return HS512, nil
	}
	return UnknownAlgorithm, fmt.Errorf("unknown algorithm: %v", a)
}

func outputPrefixTypeFromKIDStrategy(s KIDStrategy) (tinkpb.OutputPrefixType, error) {
	switch s {
	case CustomKID:
		return tinkpb.OutputPrefixType_RAW, nil
	case IgnoredKID:
		return tinkpb.OutputPrefixType_RAW, nil
	case Base64EncodedKeyIDAsKID:
		return tinkpb.OutputPrefixType_TINK, nil
	}
	return tinkpb.OutputPrefixType_UNKNOWN_PREFIX, fmt.Errorf("unknown KID strategy: %v", s)
}

func kidStrategyFromOutputPrefixType(s tinkpb.OutputPrefixType) (KIDStrategy, error) {
	switch s {
	case tinkpb.OutputPrefixType_RAW:
		return IgnoredKID, nil
	case tinkpb.OutputPrefixType_TINK:
		return Base64EncodedKeyIDAsKID, nil
	}
	return UnknownKIDStrategy, fmt.Errorf("unknown output prefix type: %v", s)
}

func (s *parametersSerializer) Serialize(p key.Parameters) (*tinkpb.KeyTemplate, error) {
	if p == nil {
		return nil, fmt.Errorf("parameters can't be nil")
	}
	params, ok := p.(*Parameters)
	if !ok {
		return nil, fmt.Errorf("invalid parameters type: got %T, want %T", p, (*Parameters)(nil))
	}
	keyFormat := &jwthmacpb.JwtHmacKeyFormat{
		Algorithm: algorithmToProto(params.Algorithm()),
		KeySize:   uint32(params.KeySizeInBytes()),
		Version:   0,
	}
	serializedKeyFormat, err := proto.Marshal(keyFormat)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JwtHmacKeyFormat: %v", err)
	}
	outputPrefixType, err := outputPrefixTypeFromKIDStrategy(params.kidStrategy)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          keyTypeURL,
		Value:            serializedKeyFormat,
		OutputPrefixType: outputPrefixType,
	}, nil
}

type parametersParser struct{}

var _ protoserialization.ParametersParser = (*parametersParser)(nil)

func (s *parametersParser) Parse(kt *tinkpb.KeyTemplate) (key.Parameters, error) {
	if kt == nil {
		return nil, fmt.Errorf("key template can't be nil")
	}
	if kt.GetTypeUrl() != keyTypeURL {
		return nil, fmt.Errorf("invalid type URL: got %q, want %q", kt.GetTypeUrl(), keyTypeURL)
	}
	keyFormat := &jwthmacpb.JwtHmacKeyFormat{}
	if err := proto.Unmarshal(kt.GetValue(), keyFormat); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JwtHmacKeyFormat: %v", err)
	}
	if keyFormat.GetVersion() != 0 {
		return nil, fmt.Errorf("invalid version: got %d, want 0", keyFormat.GetVersion())
	}
	kidStrategy, err := kidStrategyFromOutputPrefixType(kt.GetOutputPrefixType())
	if err != nil {
		return nil, err
	}
	algorithm, err := algorithmFromProto(keyFormat.GetAlgorithm())
	if err != nil {
		return nil, err
	}
	return NewParameters(int(keyFormat.GetKeySize()), kidStrategy, algorithm)
}
