# Images

Policies in this folder are enforcing different aspect of an OCI image. In particuliar, these policies generally:

- Fetch the OCI Image Configuration with the [`fetchConfigFile`](https://docs.sigstore.dev/policy-controller/overview/#including-oci-image-configuration-for-cip-level-policies) option
- Match a set of remote image for which to apply a static check.
