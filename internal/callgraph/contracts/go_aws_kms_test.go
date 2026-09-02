// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedGoIncludesAWSKMSContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	tests := []struct {
		method, library, role string
		arity                 int
	}{
		{"github.com/aws/aws-sdk-go/service/kms.(*KMS).Encrypt", "aws-kms", "operation", 1},
		{"github.com/aws/aws-sdk-go/service/kms.(*KMS).GenerateDataKey", "aws-kms", "factory", 1},
		{"github.com/aws/aws-sdk-go-v2/service/kms.(*Client).Sign", "aws-kms-v2", "operation", 3},
		{"github.com/aws/aws-sdk-go-v2/service/kms.(*Client).GenerateRandom", "aws-kms-v2", "output", 3},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != tt.library || contract.Role != tt.role || contract.Return.Confidence != "high" {
				t.Fatalf("contract = %#v, want %s %s/high", contract, tt.library, tt.role)
			}
		})
	}
}
