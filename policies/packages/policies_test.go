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
		name:   "log4shell with cyclone sbom",
		policy: "log4shell-cue.yaml",
		image:  "ghcr.io/mattmoor/sbom-attestations/cyclone-test@sha256:ba4037061b76ad8f306dd9e442877236015747ec42141caf504dc0df4d10708d",
		check: All(
			NoWarnings,
			CheckError("Error: CycloneDX SBOM contains package version 2.14.1 which is vulnerable to Log4Shell (CVE-2021-44228)"),
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
