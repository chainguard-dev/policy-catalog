/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package workloads_test

import (
	"testing"

	. "github.com/chainguard-dev/policy-catalog/pkg/test"
)

const regoErrMsg = "policy is not compliant for query 'isCompliant = data.sigstore.isCompliant'"

func TestPolicies(t *testing.T) {
	tests := []struct {
		name     string
		policy   string
		resource string

		check Check
	}{{
		name:     "no-host-namespaces",
		policy:   "host-namespaces-cue.yaml",
		resource: "testdata/good-pod.yaml",
		check:    All(NoWarnings, NoErrors),
	}, {
		name:     "host-network-is-disallowed",
		policy:   "host-namespaces-cue.yaml",
		resource: "testdata/pod-host-network.yaml",
		check:    All(CheckWarning("spec.hostNetwork"), NoErrors),
	}, {
		name:     "host-ipc-is-disallowed",
		policy:   "host-namespaces-cue.yaml",
		resource: "testdata/pod-host-ipc.yaml",
		check:    All(CheckWarning("spec.hostIPC"), NoErrors),
	}, {
		name:     "host-pid-is-disallowed",
		policy:   "host-namespaces-cue.yaml",
		resource: "testdata/pod-host-pid.yaml",
		check:    All(CheckWarning("spec.hostPID"), NoErrors),
	}, {
		name:     "no-host-namespaces",
		policy:   "host-namespaces-rego.yaml",
		resource: "testdata/good-pod.yaml",
		check:    All(NoWarnings, NoErrors),
	}, {
		name:     "host-network-is-disallowed",
		policy:   "host-namespaces-rego.yaml",
		resource: "testdata/pod-host-network.yaml",
		check:    All(CheckWarning(regoErrMsg), NoErrors),
	}, {
		name:     "host-ipc-is-disallowed",
		policy:   "host-namespaces-rego.yaml",
		resource: "testdata/pod-host-ipc.yaml",
		check:    All(CheckWarning(regoErrMsg), NoErrors),
	}, {
		name:     "host-pid-is-disallowed",
		policy:   "host-namespaces-rego.yaml",
		resource: "testdata/pod-host-pid.yaml",
		check:    All(CheckWarning(regoErrMsg), NoErrors),
	}, {
		name:     "no-privileged-containers",
		policy:   "privileged-containers-cue.yaml",
		resource: "testdata/good-pod.yaml",
		check:    All(NoWarnings, NoErrors),
	}, {
		name:     "privileged-containers",
		policy:   "privileged-containers-cue.yaml",
		resource: "testdata/pod-containers-privileged.yaml",
		check:    All(CheckWarning("spec.containers.0.securityContext.privileged"), NoErrors),
	}, {
		name:     "privileged-init-containers",
		policy:   "privileged-containers-cue.yaml",
		resource: "testdata/pod-init-containers-privileged.yaml",
		check:    All(CheckWarning("spec.initContainers.0.securityContext.privileged"), NoErrors),
	}, {
		name:     "privileged-ephemeral-containers",
		policy:   "privileged-containers-cue.yaml",
		resource: "testdata/pod-ephemeral-containers-privileged.yaml",
		check:    All(CheckWarning("spec.ephemeralContainers.0.securityContext.privileged"), NoErrors),
	}, {
		name:     "unprivileged-all-containers",
		policy:   "privileged-containers-cue.yaml",
		resource: "testdata/pod-all-unprivileged.yaml",
		check:    All(NoWarnings, NoErrors),
	}, {
		name:     "no-host-ports",
		policy:   "host-ports-cue.yaml",
		resource: "testdata/good-pod.yaml",
		check:    All(NoWarnings, NoErrors),
	}, {
		name:     "containers-host-port",
		policy:   "host-ports-cue.yaml",
		resource: "testdata/pod-containers-host-port.yaml",
		check:    All(CheckWarning("spec.containers.0.ports.0.hostPort"), NoErrors),
	}, {
		name:     "init-containers-host-port",
		policy:   "host-ports-cue.yaml",
		resource: "testdata/pod-init-containers-host-port.yaml",
		check:    All(CheckWarning("spec.initContainers.0.ports.0.hostPort"), NoErrors),
	}, {
		name:     "ephemeral-containers-host-port",
		policy:   "host-ports-cue.yaml",
		resource: "testdata/pod-ephemeral-containers-host-port.yaml",
		check:    All(CheckWarning("spec.ephemeralContainers.0.ports.0.hostPort"), NoErrors),
	}, {
		name:     "no-non-default-capabilities",
		policy:   "non-default-capabilities-cue.yaml",
		resource: "testdata/good-pod.yaml",
		check:    All(NoWarnings, NoErrors),
	}, {
		name:     "containers-add-cap-net-admin",
		policy:   "non-default-capabilities-cue.yaml",
		resource: "testdata/pod-containers-add-net-admin.yaml",
		check:    All(CheckWarning("spec.containers.0.securityContext.capabilities.add.0"), NoErrors),
	}, {
		name:     "init-containers-add-cap-net-admin",
		policy:   "non-default-capabilities-cue.yaml",
		resource: "testdata/pod-init-containers-add-net-admin.yaml",
		check:    All(CheckWarning("spec.initContainers.0.securityContext.capabilities.add.0"), NoErrors),
	}, {
		name:     "ephemeral-containers-add-cap-net-admin",
		policy:   "non-default-capabilities-cue.yaml",
		resource: "testdata/pod-ephemeral-containers-add-net-admin.yaml",
		check:    All(CheckWarning("spec.ephemeralContainers.0.securityContext.capabilities.add.0"), NoErrors),
	}, {
		name:     "capabilities-add-setuid",
		policy:   "non-default-capabilities-cue.yaml",
		resource: "testdata/pod-add-setuid.yaml",
		check:    All(NoWarnings, NoErrors),
	}, {
		name:     "no-hostpath-volumes",
		policy:   "hostpath-volumes-cue.yaml",
		resource: "testdata/good-pod.yaml",
		check:    All(NoWarnings, NoErrors),
	}, {
		name:     "hostpath-volumes",
		policy:   "hostpath-volumes-cue.yaml",
		resource: "testdata/pod-hostpath-volume.yaml",
		check:    All(CheckWarning("spec.volumes.0.hostPath.path"), NoErrors),
	}, {
		name:     "no-proc-mount",
		policy:   "non-default-proc-mount-cue.yaml",
		resource: "testdata/good-pod.yaml",
		check:    All(NoWarnings, NoErrors),
	}, {
		name:     "containers-proc-mount",
		policy:   "non-default-proc-mount-cue.yaml",
		resource: "testdata/pod-containers-proc-mount.yaml",
		check:    All(CheckWarning("spec.containers.0.securityContext.procMount"), NoErrors),
	}, {
		name:     "init-containers-proc-mount",
		policy:   "non-default-proc-mount-cue.yaml",
		resource: "testdata/pod-init-containers-proc-mount.yaml",
		check:    All(CheckWarning("spec.initContainers.0.securityContext.procMount"), NoErrors),
	}, {
		name:     "ephemeral-containers-proc-mount",
		policy:   "non-default-proc-mount-cue.yaml",
		resource: "testdata/pod-ephemeral-containers-proc-mount.yaml",
		check:    All(CheckWarning("spec.ephemeralContainers.0.securityContext.procMount"), NoErrors),
	}, {
		name:     "no-proc-mount-rego",
		policy:   "non-default-proc-mount-rego.yaml",
		resource: "testdata/good-pod.yaml",
		check:    All(NoWarnings, NoErrors),
	}, {
		name:     "containers-proc-mount-rego",
		policy:   "non-default-proc-mount-rego.yaml",
		resource: "testdata/pod-containers-proc-mount.yaml",
		check:    All(CheckWarning(regoErrMsg), NoErrors),
	}, {
		name:     "init-containers-proc-mount-rego",
		policy:   "non-default-proc-mount-rego.yaml",
		resource: "testdata/pod-init-containers-proc-mount.yaml",
		check:    All(CheckWarning(regoErrMsg), NoErrors),
	}, {
		name:     "ephemeral-containers-proc-mount-rego",
		policy:   "non-default-proc-mount-rego.yaml",
		resource: "testdata/pod-ephemeral-containers-proc-mount.yaml",
		check:    All(CheckWarning(regoErrMsg), NoErrors),
	}, {
		name:     "no-unsafe-sysctls",
		policy:   "unsafe-sysctls-mask-cue.yaml",
		resource: "testdata/good-pod.yaml",
		check:    All(NoWarnings, NoErrors),
	}, {
		name:     "unsafe-sysctls",
		policy:   "unsafe-sysctls-mask-cue.yaml",
		resource: "testdata/pod-unsafe-sysctls.yaml",
		check:    All(CheckWarning("spec.securityContext.sysctls.0.name"), NoErrors),
	}, {
		name:     "no-priv-esc",
		policy:   "disallow-privilege-escalation-cue.yaml",
		resource: "testdata/good-pod.yaml",
		check:    All(NoWarnings, NoErrors),
	}, {
		name:     "containers-allow-priv-esc",
		policy:   "disallow-privilege-escalation-cue.yaml",
		resource: "testdata/pod-containers-allow-privesc.yaml",
		check: All(
			CheckWarning("spec.containers.0.name"),
			CheckWarning("securityContext.allowPrivilegeEscalation must be false"),
			NoErrors,
		),
	}, {
		name:     "containers-allow-priv-esc-explicit",
		policy:   "disallow-privilege-escalation-cue.yaml",
		resource: "testdata/pod-containers-allow-privesc-explicit.yaml",
		check: All(
			CheckWarning("spec.containers.0.name"),
			CheckWarning("securityContext.allowPrivilegeEscalation must be false"),
			NoErrors,
		),
	}, {
		name:     "init-containers-allow-priv-esc",
		policy:   "disallow-privilege-escalation-cue.yaml",
		resource: "testdata/pod-init-containers-allow-privesc.yaml",
		check: All(
			CheckWarning("spec.initContainers.0.name"),
			CheckWarning("securityContext.allowPrivilegeEscalation must be false"),
			NoErrors,
		),
	}, {
		name:     "ephemeral-containers-allow-priv-esc",
		policy:   "disallow-privilege-escalation-cue.yaml",
		resource: "testdata/pod-ephemeral-containers-allow-privesc.yaml",
		check: All(
			CheckWarning("spec.ephemeralContainers.0.name"),
			CheckWarning("securityContext.allowPrivilegeEscalation must be false"),
			NoErrors,
		),
	}, {
		name:     "no-unconfined-seccomp",
		policy:   "baseline-seccomp-cue.yaml",
		resource: "testdata/good-pod.yaml",
		check:    All(NoWarnings, NoErrors),
	}, {
		name:     "unconfined-pod-seccomp",
		policy:   "baseline-seccomp-cue.yaml",
		resource: "testdata/pod-unconfined-seccomp.yaml",
		check:    All(CheckWarning("spec.securityContext.seccompProfile.type"), NoErrors),
	}, {
		name:     "unconfined-pod-containers-seccomp",
		policy:   "baseline-seccomp-cue.yaml",
		resource: "testdata/pod-containers-unconfined-seccomp.yaml",
		check:    All(CheckWarning("spec.containers.0.securityContext.seccompProfile.type"), NoErrors),
	}, {
		name:     "unconfined-pod-init-containers-seccomp",
		policy:   "baseline-seccomp-cue.yaml",
		resource: "testdata/pod-init-containers-unconfined-seccomp.yaml",
		check:    All(CheckWarning("spec.initContainers.0.securityContext.seccompProfile.type"), NoErrors),
	}, {
		name:     "unconfined-pod-ephemeral-containers-seccomp",
		policy:   "baseline-seccomp-cue.yaml",
		resource: "testdata/pod-ephemeral-containers-unconfined-seccomp.yaml",
		check:    All(CheckWarning("spec.ephemeralContainers.0.securityContext.seccompProfile.type"), NoErrors),
	}, {
		name:     "restricted-capabilities",
		policy:   "restricted-capabilities-cue.yaml",
		resource: "testdata/good-pod.yaml",
		check:    All(NoWarnings, NoErrors),
	}, {
		name:     "restricted-capabilities",
		policy:   "restricted-capabilities-cue.yaml",
		resource: "testdata/good-pod.yaml",
		check:    All(NoWarnings, NoErrors),
	}, {
		name:     "containers-add-bad-cap",
		policy:   "restricted-capabilities-cue.yaml",
		resource: "testdata/pod-containers-add-disallowed-cap.yaml",
		check:    All(CheckWarning("spec.containers.0.securityContext.capabilities.add.0"), NoErrors),
	}, {
		name:     "init-containers-add-bad-cap",
		policy:   "restricted-capabilities-cue.yaml",
		resource: "testdata/pod-init-containers-add-disallowed-cap.yaml",
		check:    All(CheckWarning("spec.initContainers.0.securityContext.capabilities.add.0"), NoErrors),
	}, {
		name:     "ephemeral-containers-add-bad-cap",
		policy:   "restricted-capabilities-cue.yaml",
		resource: "testdata/pod-ephemeral-containers-add-disallowed-cap.yaml",
		check:    All(CheckWarning("spec.ephemeralContainers.0.securityContext.capabilities.add.0"), NoErrors),
	}, {
		name:     "containers-missing-drop",
		policy:   "restricted-capabilities-cue.yaml",
		resource: "testdata/pod-containers-missing-drop.yaml",
		check: All(
			CheckWarning("spec.containers.0.name"),
			CheckWarning("container does not drop ALL capabilities"),
			NoErrors,
		),
	}, {
		name:     "init-containers-missing-drop",
		policy:   "restricted-capabilities-cue.yaml",
		resource: "testdata/pod-init-container-missing-drop.yaml",
		check: All(
			CheckWarning("spec.initContainers.0.name"),
			CheckWarning("init container does not drop ALL capabilities"),
			NoErrors,
		),
	}, {
		name:     "ephemeral-containers-missing-drop",
		policy:   "restricted-capabilities-cue.yaml",
		resource: "testdata/pod-ephemeral-container-missing-drop.yaml",
		check: All(
			CheckWarning("spec.ephemeralContainers.0.name"),
			CheckWarning("ephemeral container does not drop ALL capabilities"),
			NoErrors,
		),
	}, {
		name:     "no-runasuser-root",
		policy:   "disallow-runasuser-root-cue.yaml",
		resource: "testdata/good-pod.yaml",
		check:    All(NoWarnings, NoErrors),
	}, {
		name:     "containers-runasuser-root",
		policy:   "disallow-runasuser-root-cue.yaml",
		resource: "testdata/pod-containers-runasuser-root.yaml",
		check:    All(CheckWarning("spec.containers.0.securityContext.runAsUser"), NoErrors),
	}, {
		name:     "init-containers-runasuser-root",
		policy:   "disallow-runasuser-root-cue.yaml",
		resource: "testdata/pod-init-containers-runasuser-root.yaml",
		check:    All(CheckWarning("spec.initContainers.0.securityContext.runAsUser"), NoErrors),
	}, {
		name:     "ephemeral-containers-runasuser-root",
		policy:   "disallow-runasuser-root-cue.yaml",
		resource: "testdata/pod-ephemeral-containers-runasuser-root.yaml",
		check:    All(CheckWarning("spec.ephemeralContainers.0.securityContext.runAsUser"), NoErrors),
	}, {
		name:     "no-disallowed-volumes",
		policy:   "restricted-volumes-cue.yaml",
		resource: "testdata/good-pod.yaml",
		check:    All(NoWarnings, NoErrors),
	}, {
		name:     "disallowed-volume",
		policy:   "restricted-volumes-cue.yaml",
		resource: "testdata/pod-hostpath-volume.yaml",
		check: All(
			CheckWarning("spec.volumes.0"),
			CheckWarning("hostPath"),
			NoErrors,
		),
	}, {
		name:     "no-host-process",
		policy:   "host-process-cue.yaml",
		resource: "testdata/good-pod.yaml",
		check:    All(NoWarnings, NoErrors),
	}, {
		name:     "pod-host-process",
		policy:   "host-process-cue.yaml",
		resource: "testdata/pod-hostprocess.yaml",
		check:    All(CheckWarning("spec.securityContext.windowsOptions.hostProcess"), NoErrors),
	}, {
		name:     "containers-host-process",
		policy:   "host-process-cue.yaml",
		resource: "testdata/pod-containers-hostprocess.yaml",
		check:    All(CheckWarning("spec.containers.0.securityContext.windowsOptions.hostProcess"), NoErrors),
	}, {
		name:     "init-containers-host-process",
		policy:   "host-process-cue.yaml",
		resource: "testdata/pod-init-containers-hostprocess.yaml",
		check:    All(CheckWarning("spec.initContainers.0.securityContext.windowsOptions.hostProcess"), NoErrors),
	}, {
		name:     "ephemeral-containers-host-process",
		policy:   "host-process-cue.yaml",
		resource: "testdata/pod-ephemeral-containers-hostprocess.yaml",
		check:    All(CheckWarning("spec.ephemeralContainers.0.securityContext.windowsOptions.hostProcess"), NoErrors),
	}, {
		name:     "no-host-process-rego",
		policy:   "host-process-rego.yaml",
		resource: "testdata/good-pod.yaml",
		check:    All(NoWarnings, NoErrors),
	}, {
		name:     "pod-host-process-rego",
		policy:   "host-process-rego.yaml",
		resource: "testdata/pod-hostprocess.yaml",
		check:    All(CheckWarning(regoErrMsg), NoErrors),
	}, {
		name:     "containers-host-process-rego",
		policy:   "host-process-rego.yaml",
		resource: "testdata/pod-containers-hostprocess.yaml",
		check:    All(CheckWarning(regoErrMsg), NoErrors),
	}, {
		name:     "init-containers-host-process-rego",
		policy:   "host-process-rego.yaml",
		resource: "testdata/pod-init-containers-hostprocess.yaml",
		check:    All(CheckWarning(regoErrMsg), NoErrors),
	}, {
		name:     "ephemeral-containers-host-process-rego",
		policy:   "host-process-rego.yaml",
		resource: "testdata/pod-ephemeral-containers-hostprocess.yaml",
		check:    All(CheckWarning(regoErrMsg), NoErrors),
	}, {
		name:     "no-selinux-problems",
		policy:   "selinux-restrictions-cue.yaml",
		resource: "testdata/good-pod.yaml",
		check:    All(NoWarnings, NoErrors),
	}, {
		name:     "pod-selinux-user",
		policy:   "selinux-restrictions-cue.yaml",
		resource: "testdata/pod-selinux-user.yaml",
		check:    All(CheckWarning("spec.securityContext.seLinuxOptions.user"), NoErrors),
	}, {
		name:     "pod-selinux-role",
		policy:   "selinux-restrictions-cue.yaml",
		resource: "testdata/pod-selinux-role.yaml",
		check:    All(CheckWarning("spec.securityContext.seLinuxOptions.role"), NoErrors),
	}, {
		name:     "pod-selinux-type",
		policy:   "selinux-restrictions-cue.yaml",
		resource: "testdata/pod-selinux-type.yaml",
		check:    All(CheckWarning("spec.securityContext.seLinuxOptions.type"), NoErrors),
	}, {
		name:     "pod-containers-selinux-type",
		policy:   "selinux-restrictions-cue.yaml",
		resource: "testdata/pod-containers-selinux-type.yaml",
		check:    All(CheckWarning("spec.containers.0.securityContext.seLinuxOptions.type"), NoErrors),
	}, {
		name:     "pod-init-containers-selinux-user",
		policy:   "selinux-restrictions-cue.yaml",
		resource: "testdata/pod-init-containers-selinux-user.yaml",
		check:    All(CheckWarning("spec.initContainers.0.securityContext.seLinuxOptions.user"), NoErrors),
	}, {
		name:     "pod-ephemeral-containers-selinux-role",
		policy:   "selinux-restrictions-cue.yaml",
		resource: "testdata/pod-ephemeral-containers-selinux-role.yaml",
		check:    All(CheckWarning("spec.ephemeralContainers.0.securityContext.seLinuxOptions.role"), NoErrors),
	}, {
		name:     "no-apparmor-problems",
		policy:   "disallow-apparmor-override-cue.yaml",
		resource: "testdata/good-pod.yaml",
		check:    All(NoWarnings, NoErrors),
	}, {
		name:     "no-apparmor-problems-runtime-default",
		policy:   "disallow-apparmor-override-cue.yaml",
		resource: "testdata/good-pod-apparmor-rt-default.yaml",
		check:    All(NoWarnings, NoErrors),
	}, {
		name:     "no-apparmor-problems-localhost",
		policy:   "disallow-apparmor-override-cue.yaml",
		resource: "testdata/good-pod-apparmor-localhost.yaml",
		check:    All(NoWarnings, NoErrors),
	}, {
		name:     "bad-apparmor-annotation",
		policy:   "disallow-apparmor-override-cue.yaml",
		resource: "testdata/pod-override-apparmor.yaml",
		check: All(
			CheckWarning("spec.containers.0"), CheckWarning("other"),
			NoErrors,
		),
	}, {
		name:     "bad-apparmor-annotation-init",
		policy:   "disallow-apparmor-override-cue.yaml",
		resource: "testdata/pod-override-init-apparmor.yaml",
		check: All(
			CheckWarning("spec.initContainers.0"), CheckWarning("other"),
			NoErrors,
		),
	}, {
		name:     "bad-apparmor-annotation-debug",
		policy:   "disallow-apparmor-override-cue.yaml",
		resource: "testdata/pod-override-debug-apparmor.yaml",
		check: All(
			CheckWarning("spec.ephemeralContainers.0"), CheckWarning("other"),
			NoErrors,
		),
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
