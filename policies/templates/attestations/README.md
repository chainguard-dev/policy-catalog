# Attestations

This directory contains policies that validate trust levels on attestations. For more information, please see the [Sigstore](https://www.sigstore.dev/) [documentation](https://docs.sigstore.dev/policy-controller/overview#configuring-policy-that-validates-attestations) on validating attestations.

## Attestation with a cosign vulnerability report

To generate a cosign vulnerability scan record, you can use Trivy and use Cosign to attach it as an attestation to a container image:

```shell
trivy image --format cosign-vuln --output vuln.json <IMAGE>
cosign attest --key /path/to/cosign.key --type vuln --predicate vuln.json <IMAGE>
```

You can verify the attestation has been attached to the image:

```shell
cosign verify-attestation --key /path/to/cosign.pub --type vuln <IMAGE>
```
