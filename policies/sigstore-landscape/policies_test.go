/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package components_test

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
		name:   "certmanager-webhook-is-signed",
		policy: "certmanager-signed.yaml",
		image:  "quay.io/jetstack/cert-manager-webhook@sha256:4ab2982a220e1c719473d52d8463508422ab26e92664732bfc4d96b538af6b8a",
		check:  All(NoWarnings, NoErrors),
	}, {
		name:   "certmanager-controller-is-signed",
		policy: "certmanager-signed.yaml",
		image:  "quay.io/jetstack/cert-manager-controller@sha256:cd9bf3d48b6b8402a2a8b11953f9dc0275ba4beec14da47e31823a0515cde7e2",
		check:  All(NoWarnings, NoErrors),
	}, {
		name:   "certmanager-cainjector-is-signed",
		policy: "certmanager-signed.yaml",
		image:  "quay.io/jetstack/cert-manager-cainjector@sha256:df7f0b5186ddb84eccb383ed4b10ec8b8e2a52e0e599ec51f98086af5f4b4938",
		check:  All(NoWarnings, NoErrors),
	}, {
		name:   "istio-pilot-is-signed",
		policy: "istio-signed.yaml",
		image:  "index.docker.io/istio/pilot@sha256:dd04a4347f5ae42951b3e809341f82718f8be10797e5c62f925479ef594d7e7d",
		check:  All(NoWarnings, NoErrors),
	}, {
		name:   "istio-proxy-is-signed",
		policy: "istio-signed.yaml",
		image:  "index.docker.io/istio/proxyv2@sha256:8fca4171c07af5b5885600d29d781a07d64704851e7e1282d39b9dd27ec1fa76",
		check:  All(NoWarnings, NoErrors),
	}, {
		name:   "distroless-static-is-signed",
		policy: "google-distroless-signed.yaml",
		image:  "gcr.io/distroless/static",
		check:  All(NoWarnings, NoErrors),
	}, {
		name:   "distroless-base-debug-is-signed",
		policy: "google-distroless-signed.yaml",
		image:  "gcr.io/distroless/base:debug",
		check:  All(NoWarnings, NoErrors),
	}, {
		name:   "distroless-base-debug-is-signed",
		policy: "google-distroless-signed.yaml",
		image:  "gcr.io/distroless/base:debug",
		check:  All(NoWarnings, NoErrors),
	}, {
		name:   "kube state metrics before it was signed (fails)",
		policy: "kubernetes-signed.yaml",
		image:  "registry.k8s.io/kube-state-metrics/kube-state-metrics:v2.5.0",
		check:  All(NoWarnings, CheckError("no signatures found for image")),
	}, {
		name:   "kube state metrics is signed",
		policy: "kubernetes-signed.yaml",
		// 2.7.0 is latest, but affected by:
		// https://github.com/kubernetes/release/issues/2789
		// I'm not checking that because if they decide to re-sign, it will
		// break our tests!
		image: "registry.k8s.io/kube-state-metrics/kube-state-metrics:v2.6.0",
		check: All(NoWarnings, NoErrors),
	}, {
		name:   "kubernetes apiserver is signed",
		policy: "kubernetes-signed.yaml",
		image:  "registry.k8s.io/kube-apiserver:v1.26.0",
		check:  All(NoWarnings, NoErrors),
	}, {
		name:   "tekton pipelines controller image is signed",
		policy: "tekton-signed.yaml",
		image:  "gcr.io/tekton-releases/github.com/tektoncd/pipeline/cmd/controller",
		check:  All(NoWarnings, NoErrors),
	}, {
		name:   "tekton chains controller image is signed",
		policy: "tekton-signed.yaml",
		image:  "gcr.io/tekton-releases/github.com/tektoncd/chains/cmd/controller",
		check:  All(NoWarnings, NoErrors),
	}, {
		name:   "knative net-counter controller image is signed",
		policy: "knative-signed.yaml",
		// We should try to make this use :latest as an early-warning system,
		// but the knative release process seems to apply :latest to whichever
		// patch release pushes last right now.
		image: "gcr.io/knative-releases/knative.dev/net-contour/cmd/controller:v1.8.1",
		check: All(NoWarnings, NoErrors),
	}, {
		name:   "karpenter v0.20.0 is signed",
		policy: "karpenter-signed.yaml",
		image:  "public.ecr.aws/karpenter/controller:v0.20.0",
		check:  All(NoWarnings, NoErrors),
	}, {
		name:   "karpenter v0.20.1 is signed",
		policy: "karpenter-signed.yaml",
		// Historically the Karpenter folks had a problem where the patch
		// releases were getting signed by humans.  This checks that the 0.20.1
		// release was properly signed!
		image: "public.ecr.aws/karpenter/controller:v0.20.1",
		check: All(NoWarnings, NoErrors),
	}, {
		name:   "karpenter v0.18.1 is signed improperly",
		policy: "karpenter-signed.yaml",
		// Check that we reject the 0.18.1 release, which was signed by a
		// human contributor instead of the automation.
		image: "public.ecr.aws/karpenter/controller:v0.18.1",
		check: All(NoWarnings, CheckError("none of the expected identities matched what was in the certificate")),
	}, {
		name:   "KEDA core is signed",
		policy: "keda-signed.yaml",
		image:  "ghcr.io/kedacore/keda:2.9.0",
		check:  All(NoWarnings, NoErrors),
	}, {
		name:   "KEDA core is signed (patch release)",
		policy: "keda-signed.yaml",
		image:  "ghcr.io/kedacore/keda:2.9.1",
		check:  All(NoWarnings, NoErrors),
	}, {
		name:   "Cilium is signed 1.13+",
		policy: "cilium-signed.yaml",
		image:  "index.docker.io/cilium/cilium:v1.13.0-rc3",
		check:  All(NoWarnings, NoErrors),
	}, {
		name:   "Cilium wasn't signed in 1.12",
		policy: "cilium-signed.yaml",
		image:  "index.docker.io/cilium/cilium:v1.12.4",
		check:  All(NoWarnings, CheckError("no signatures found for image")),
	}, {
		name:   "Flux source-controller is signed (helm)",
		policy: "flux-signed.yaml",
		image:  "ghcr.io/fluxcd/helm-controller:v0.31.2",
		check:  All(NoWarnings, NoErrors),
	}, {
		name:   "Flux source-controller is signed (kustomzise)",
		policy: "flux-signed.yaml",
		image:  "ghcr.io/fluxcd/kustomize-controller:v0.35.1",
		check:  All(NoWarnings, NoErrors),
	}, {
		name:   "Flux source-controller is signed (source)",
		policy: "flux-signed.yaml",
		image:  "ghcr.io/fluxcd/source-controller:v0.36.1",
		check:  All(NoWarnings, NoErrors),
	}, {
		name:   "Flux source-controller is signed (notification)",
		policy: "flux-signed.yaml",
		image:  "ghcr.io/fluxcd/notification-controller:v0.32.1",
		check:  All(NoWarnings, NoErrors),
	}, {
		name:   "Kyverno is signed",
		policy: "kyverno-signed.yaml",
		image:  "ghcr.io/kyverno/kyverno:v1.8.4",
		check:  All(NoWarnings, NoErrors),
	}, {
		name:   "Linkerd is signed (edge)",
		policy: "linkerd-signed.yaml",
		image:  "ghcr.io/linkerd/controller:edge-22.12.1",
		check:  All(NoWarnings, NoErrors),
	}, {
		name:   "Linkerd is signed (stable)",
		policy: "linkerd-signed.yaml",
		image:  "ghcr.io/linkerd/controller:stable-2.12.3",
		check:  All(NoWarnings, NoErrors),
	}, {
		name:   "Shipwright is signed",
		policy: "shipwright-signed.yaml",
		image:  "ghcr.io/shipwright-io/build/shipwright-build-controller:v0.11.0",
		check:  All(NoWarnings, NoErrors),
	}, {
		name:   "Keptn is signed",
		policy: "keptn-signed.yaml",
		image:  "ghcr.io/keptn/api:1.0.0",
		check:  All(NoWarnings, NoErrors),
	}, {
		name:   "Policy-Controller is signed",
		policy: "policy-controller-signed.yaml",
		image:  "ghcr.io/sigstore/policy-controller/policy-webhook:v0.7.0",
		check:  All(NoWarnings, NoErrors),
	}}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
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
