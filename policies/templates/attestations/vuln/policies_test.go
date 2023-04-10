/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package images_test

import (
	"testing"

	. "github.com/chainguard-dev/policy-catalog/pkg/test"
)

func TestPolicies(t *testing.T) {
	tests := []struct {
		name   string
		policy string
		image  string

		check Check
	}{{
		name:   "vuln no high or critical(fails)",
		policy: "vuln-no-high-or-critical-rego.yaml",
		image:  "hectorj2f/harbor-registry:latest", // NOTE: Use a custom image to use the v2 predicates
		check: All(
			NoWarnings,
			CheckError("Found HIGH '9' and CRITICAL '1' vulnerabilities"),
		),
	}, {
		name:   "vuln no high or critical(pass)",
		policy: "vuln-no-high-or-critical-rego.yaml",
		image:  "hectorj2f/trivy:latest", // NOTE: Use a custom image to use the v2 predicates
		check: All(
			NoWarnings,
			NoErrors,
		),
	}, {
		name:   "vuln maximum scan age (warns)",
		policy: "vuln-maximum-scan-age-rego.yaml",
		image:  "ghcr.io/chipzoller/zulu:latest",
		check: All(
			CheckWarning("policy 0: invalid value: cosign.sigstore.dev/attestation/vuln/v1: spec.authorities[0].attestations.predicateType\ndeprecated value, please use RFC 3986 conformant values"),
			CheckError("Scan exceeds maximum allowed age"),
		),
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := Run(test.policy, test.image)
			if err != nil {
				t.Fatalf("ptest.Run() = %v", err)
			}
			if test.check != nil {
				test.check(t, res)
			}
		})
	}
}
