# Policy Catalog

This policy catalog contains `ClusterImagePolicy` resources for implementing security policies on Kubernetes clusters using Sigstore’s [Policy Controller](https://github.com/sigstore/policy-controller) or [Chainguard Enforce](https://www.chainguard.dev/chainguard-enforce). These policies set conditions for admitting images into your cluster, such as requiring signed images, enforcing SBOM attestations, or ensuring Log4Shell is not running. Many of these policies can be used out of the box but you can also modify them for your own use case.

Both Policy Controller and Enforce support the use of CUE and Rego policy restraints to enable fully-customizable policy creation. Designed specifically for software supply chain security needs, Policy Controller and Enforce are both integrated with Sigstore's suite of tools, enabling you to leverage policy restraints based on verifiable supply chain metadata from [Cosign](https://edu.chainguard.dev/open-source/sigstore/cosign/an-introduction-to-cosign/).

We encourage community contributions, additions, and requests to the Policy Catalog. To contribute to the policy catalogue or add a new policy, please visit our [documentation on contributing](./CONTRIBUTING.md). To request the creation of a new policy, please read the [Policy requests](#policy-requests) section below.

## Policies at a glance

Policies are grouped within the [`policies`](./policies) directory according to top-level categories. These categories are as follows:

| Category | Description |
| --- | --- |
| [Benchmarks](/policies/benchmarks)| Policies that help you reach certain benchmarks, such as Pod Security Standards |
| [Images](/policies/images) | Policies that enforce certain aspects of OCI images |
| [Packages](/policies/packages) | Policies that detect specific packages in the SBOM attached to an image, such as Log4Shell |
| [Sigstore Landscape](/policies/sigstore-landscape) | Ready-to-use policies to verify the signature of various images documented in the OpenSSF Sigstore Landscape |
| [Templates](/policies/templates) | A variety of templates to start authoring custom policies |
| [Vendors](/policies/vendors) | Ready to use policies provided by commercial vendors |

### Deprecation notice of Cosign 1.0 format

Sigstore has released version 2.0 of Cosign. More information about all the changes can be read in their [blog post](https://blog.sigstore.dev/cosign-2-0-released/). Policies must be updated to support the Cosign 2.0 changes and their pipelines to generate new Cosign 2.0 attestations. Action is only needed if you use attestations in policies for the following use cases:

* In Cosign 2.0, how SPDX and CycloneDX attestations are generated has changed. The CosignPredicate envelope that wraps the predicates of SPDX and CycloneDX attestations has been removed, which violated the schema specified via the predicateType field ([more information](https://github.com/sigstore/cosign/pull/2718)). Any policies built against the SBOM data must be modified by removing the extra ‘data.’

* The predicateTypes for vulnerability and custom attestations were changed. Previously, the predicateTypes were: “cosign.sigstore.dev/attestation/vuln/v1” and “cosign.sigstore.dev/attestation/v1". These were not RFC3986 compliant; hence, they were changed to: “https://cosign.sigstore.dev/attestation/vuln/v1” and “cosign.sigstore.dev/attestation/v1". All policies should use these new formats.

As of April 2023, there is only one policy in the catalog (log4shell) that relies on attestation data, which has been updated to work with both Cosign 1.0 and 2.0. Note, however, that we will only support Cosign 1.0 until October 2023 and then as we are able.

We encourage Cosign users to upgrade their infrastructure to Cosign 2.0 to help with this transition. If you use the [GitHub action for Cosign](https://github.com/sigstore/cosign-installer), you can upgrade it by setting the release to v2.0.0.

## Using policies with Sigstore’s Policy Controller

Sigstore’s `policy-controller` is an open source Kubernetes admissions controller for creating policies based on verifiable supply-chain metadata from Cosign. To use the policies in this catalog with Policy Controller, follow our [installation guide](https://edu.chainguard.dev/open-source/sigstore/policy-controller/how-to-install-policy-controller/) and browse our growing list of [policy tutorials](https://edu.chainguard.dev/open-source/sigstore/policy-controller). For further guidance, visit Sigstore's documentation on [configuring the `policy-controller`](https://docs.sigstore.dev/policy-controller/overview/#configuring-policy-controller-clusterimagepolicy).

## Using policies with Chainguard Enforce

Customers of Chainguard Enforce can apply `CustomImagePolicy` resources through the [Chainguard Enforce Console](https://console.enforce.dev/policies/catalog) or by using `chainctl`, Chainguard Enforce’s command-line interface.

To apply policies using the Console, visit Chainguard’s documentation on [How to create policies in the Chainguard Enforce Console](https://edu.chainguard.dev/chainguard/chainguard-enforce/chainguard-enforce-kubernetes/chainguard-policies-ui/).

To get started with `chainctl`, visit Chainguard’s documentation on [How to Manage Policies with chainctl](https://edu.chainguard.dev/chainguard/chainguard-enforce/chainguard-enforce-kubernetes/chainguard-policies-cli/).

## Policy requests

We are continuing to grow our policy catalog and would love to hear from you about additional policies you would like to use. To request the creation of a policy that does not yet exist in the catalog, please open an issue with the `policy_request` template and fill in the relevant information.

While we may not be able to implement all policy requests, we will do our best to respond to these issues in a timely manner and create new policies that respond to community needs.
