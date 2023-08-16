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
		name:   "maximum image age",
		policy: "maximum-image-age-rego.yaml",
		// This has been updated recently.
		image: "cgr.dev/chainguard/nginx",
		check: All(
			NoErrors,
			NoWarnings,
		),
	}, {
		name:   "maximum image age (fails)",
		policy: "maximum-image-age-rego.yaml",
		// This was built on 2022-09-20T02:33:38Z and has stopped
		// receiving updates.
		image: "ghcr.io/distroless/static",
		check: All(
			NoErrors,
			CheckWarning("Image exceeds maximum allowed age."),
		),
	}, {
		name:   "deprecated registry warns",
		policy: "deprecated-k8s-grc-io-registry-rego.yaml",
		// This is just a random image from there, only the registry matters
		image: "k8s.gcr.io/ingress-nginx/kube-webhook-certgen:v1.1.1",
		check: All(
			NoErrors,
			CheckWarning("This repo has been deprecated: https://kubernetes.io/blog"),
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
