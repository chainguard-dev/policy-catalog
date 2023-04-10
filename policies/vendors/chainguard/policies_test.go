/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package chainguard_test

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
		name:   "static-is-signed",
		policy: "chainguard-images-signed.yaml",
		image:  "cgr.dev/chainguard/static",
		check:  All(NoErrors, NoWarnings),
	}, {
		name:   "busybox-is-signed",
		policy: "chainguard-images-signed.yaml",
		image:  "cgr.dev/chainguard/busybox",
		check:  All(NoErrors, NoWarnings),
	}, {
		name:   "old-image-does-not-verify",
		policy: "chainguard-images-signed.yaml",
		// predated the mono repo, so the signer is wrong.
		image: "cgr.dev/chainguard/static@sha256:a9650a15060275287ebf4530b34020b8d998bd2de9aea00d113c332d8c41eb0b",
		check: All(CheckError("none of the expected identities matched"), NoWarnings),
	}, {
		name:   "chainctl is signed",
		policy: "chainguard-enforce-agent-signed.yaml",
		image:  "us.gcr.io/prod-enforce-fabc/chainctl@sha256:1792f61020540158708182d3cebd17f20c65b5866c803e62d5539b8e53c860f5",
		check:  All(NoErrors, NoWarnings),
	}, {
		name:   "agent is signed",
		policy: "chainguard-enforce-agent-signed.yaml",
		image:  "us.gcr.io/prod-enforce-fabc/controlplane@sha256:25ab95c63c7148dd7ba5d8de82abcc67a9fea9e9d2be74bb675a75f4f31e3762",
		check:  All(NoErrors, NoWarnings),
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
