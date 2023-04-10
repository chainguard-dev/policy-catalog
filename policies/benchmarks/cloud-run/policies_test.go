/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package workloads_test

import (
	"testing"

	. "github.com/chainguard-dev/policy-catalog/pkg/test"
)

func TestPolicies(t *testing.T) {
	tests := []struct {
		name     string
		policy   string
		resource string

		check Check
	}{{
		name:     "no-serviceaccount-problems",
		policy:   "cloudrun-serviceaccount-rego.yaml",
		resource: "testdata/good-ksvc.yaml",
		check:    All(NoWarnings, NoErrors),
	}, {
		name:     "implicit-default-serviceaccount",
		policy:   "cloudrun-serviceaccount-rego.yaml",
		resource: "testdata/implicit-default-serviceaccount.yaml",
		check:    All(CheckWarning("serviceAccountName should be set to a non-default service account"), NoErrors),
	}, {
		name:     "explicit-default-serviceaccount",
		policy:   "cloudrun-serviceaccount-rego.yaml",
		resource: "testdata/explicit-default-serviceaccount.yaml",
		check:    All(CheckWarning("serviceAccountName should not use the Compute Engine service account"), NoErrors),
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// We use a bogus image name to ensure that these policies do not
			// reach out to the registry as part of their evaluation!
			res, err := Run(test.policy, "example.com/is-not-pulled",
				WithResource(test.resource))
			if err != nil {
				t.Fatalf("ptest.Run() = %v", err)
			}
			if test.check != nil {
				test.check(t, res)
			}
		})
	}
}
