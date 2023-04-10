# Pod Security Standards

As described in the [official documentation](https://kubernetes.io/docs/concepts/security/pod-security-standards/), the Pod Security Standards defines security profiles for securing a Kubernetes cluster.

- *Privileged*: No policies
- *Baseline*: Aims to ease adoption of common containerized workloads while preventing known privilege escalations ([reference](https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline))
- *Restricted*: Enforces current Pod hardening best practices, at the expense of some compatiblity ([reference](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted))

## Baseline profile

[Documentation](https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline)

| Name | CUE Policy | Rego Policy |
| -- | -- | -- |
| HostProcess | [host-process-cue.yaml](host-process-cue.yaml) | [host-process-rego.yaml](host-process-rego.yaml) |
| Host Namespaces | [host-namespaces-cue.yaml](host-namespaces-cue.yaml) | [host-namespaces-rego.yaml](host-namespaces-rego.yaml) |
| Privileged Containers | [privileged-containers-cue.yaml](privileged-containers-cue.yaml) | — |
| Capabilities | [non-default-capabilities-cue.yaml](non-default-capabilities-cue.yaml) | — |
| HostPath Volumes | [hostpath-volumes-cue.yaml](hostpath-volumes-cue.yaml) | — |
| Host Ports | [host-ports-cue.yaml](host-ports-cue.yaml) | [host-ports-rego.yaml](host-ports-rego.yaml) |
| AppArmor | [disallow-apparmor-override-cue.yaml](disallow-apparmor-override-cue.yaml) | — |
| SELinux | [selinux-restrictions-cue.yaml](selinux-restrictions-cue.yaml) | — |
| `/proc` Mount Type | [non-default-proc-mount-cue.yaml](non-default-proc-mount-cue.yaml) | [non-default-proc-mount-rego.yaml](non-default-proc-mount-rego.yaml) |
| Seccomp | [baseline-seccomp-cue.yaml](baseline-seccomp-cue.yaml) | — |
| Sysctls | [unsafe-sysctls-mask-cue.yaml](unsafe-sysctls-mask-cue.yaml) | — |

## Restricted profile

[Documentation](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted)

All the policies from the baseline profile, and:

| Name | CUE Policy | Rego Policy |
| -- | -- | -- |
| Volume Types | [restricted-volumes-cue.yaml](restricted-volumes-cue.yaml) | — |
| Privilege Escalation (v1.8+) | [disallow-privilege-escalation-cue.yaml](disallow-privilege-escalation-cue.yaml) | — |
| Running as Non-root user (v1.23+) | [host-process-cue.yaml](host-process-cue.yaml) | [host-process-rego.yaml](host-process-rego.yaml) |
| Seccomp (v1.19+) | — | — |
| Capabilities (v1.22+) | [restricted-capabilities-cue.yaml](restricted-capabilities-cue.yaml) | — |

