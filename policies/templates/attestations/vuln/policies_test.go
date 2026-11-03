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
	// The images below belong to third parties, so pin them by digest. A
	// mutable tag lets an upstream push change which attestations the
	// tests evaluate, and the expected results no longer hold.
	tests := []struct {
		name   string
		policy string
		image  string

		check Check
	}{{
		name:   "vuln no high or critical(fails)",
		policy: "vuln-no-high-or-critical-rego.yaml",
		image:  "hectorj2f/harbor-registry@sha256:e01d5e7f39e07f6a65cf2df25f7fb666caa7208f0888d1815b89260a013ac4fa", // latest as of 2026-11; custom image to use the v2 predicates
		check: All(
			NoWarnings,
			CheckError("Found HIGH '9' and CRITICAL '1' vulnerabilities"),
		),
	}, {
		name:   "vuln no high or critical(pass)",
		policy: "vuln-no-high-or-critical-rego.yaml",
		image:  "hectorj2f/trivy@sha256:a0f49e5739a7a2af19435a9e24e255460d195a4e6236dd7e62fda9bebd218f85", // latest as of 2026-11; custom image to use the v2 predicates
		check: All(
			NoWarnings,
			NoErrors,
		),
	}, {
		name:   "vuln maximum scan age (warns)",
		policy: "vuln-maximum-scan-age-rego.yaml",
		image:  "ghcr.io/chipzoller/zulu@sha256:ea3a2756464fcbb60378f27ea1621c9315403b78d6e28577f7b6328eff1fa343", // v0.0.18; v0.0.19+ has no vuln attestation
		check: All(
			NoWarnings,
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
