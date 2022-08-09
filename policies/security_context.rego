package kubernetes.securityContext

import data.lib.kubernetes

## Do not run pod as root
deny_pod_runAsNonRoot[msg] {
  some c
  kubernetes.pod[c]
  run_as_root := c.securityContext.runAsNonRoot
  not run_as_root
  msg = sprintf("'%s' '%s' should not run as root.", [input.kind, input.metadata.name])
}

## Do not run pod as user 0
deny_pod_runAsUser[msg] {
  input.kind == kubernetes.inputs[_]
  some c
  kubernetes.pod[c]
  run_as := c.securityContext.runAsUser
  run_as == kubernetes.forbidden_uids
  msg = sprintf("UID '%v' is forbidden on '%s' '%s'.", [run_as, input.kind, input.metadata.name])
}

# Warn about ReadOnlyRootFilesystem
warn_pod_readOnlyRootFilesystem[msg] {
  input.kind == kubernetes.inputs[_]
  some c
  kubernetes.pod[c]
  kubernetes.read_only_root_fs(c)
  msg = sprintf("readOnlyRootFilesystem should be set to true on '%s' '%s'.", [input.kind, input.metadata.name])
}

# Prohibit privilege escalation
deny_pod_privileged[msg] {
  input.kind == kubernetes.inputs[_]
  c := kubernetes.pod[_]
  kubernetes.prohibit_privilege_escalation(c)
  msg = sprintf("'%s' '%s' is not allowed to escalate privileges.", [input.kind, input.metadata.name])
}

# Missing seccompProfile
warn_pod_seccompProfile[msg] {
  input.kind == kubernetes.inputs[_]

  c := kubernetes.containers[_]
  not kubernetes.seccomp_profile(c)

  p := kubernetes.pod[_]
  not kubernetes.seccomp_profile(p)
  msg = sprintf("seccompProfile securityContext missing from '%s'.",[c.name])
}

## Container Security Context
# Required securityContext for each container
deny_container_securityCcontext[msg] {
  input.kind == kubernetes.inputs[_]
  c := kubernetes.containers[_]
  kubernetes.security_context_requirement(c)
  kubernetes.not_whitelisted_proj
  msg := sprintf("Container '%v' in '%s' '%s' should have securityContext defined.", [c.name,input.kind,input.metadata.name])
}

# Prohibit privilege escalation
deny_container_privileged[msg] {
  input.kind == kubernetes.inputs[_]
  c := kubernetes.containers[_]
  kubernetes.prohibit_privilege_escalation(c)
  kubernetes.not_whitelisted_proj
  msg = sprintf("Container '%s' in '%s' '%s' is not allowed to escalate privileges.", [c.name,input.kind,input.metadata.name])
}

# Prohibit running as root
deny_container_runAsNonRoot[msg] {
  input.kind == kubernetes.inputs[_]
  some c
  kubernetes.containers[c]
  run_as_root := c.securityContext.runAsNonRoot
  not run_as_root
  kubernetes.not_whitelisted_proj
  msg = sprintf("Container '%s' in '%s' '%s' is not allowed to run as root.", [c.name,input.kind,input.metadata.name])
}

# Prohibit running as UID 0
deny_container_runAsUser[msg] {
  input.kind == kubernetes.inputs[_]
  some c
  kubernetes.containers[c]
  run_as := c.securityContext.runAsUser
  run_as == kubernetes.forbidden_uids
  kubernetes.not_whitelisted_proj
  msg = sprintf("UID '%v' is forbidden on container '%s' in '%s' '%s'.", [run_as, c.name,input.kind, input.metadata.name])
}

deny_container_runAsUser[msg] {
  input.kind == kubernetes.inputs[_]
  c := kubernetes.containers[_]
  not kubernetes.run_as_user(c)
  kubernetes.not_whitelisted_proj
  msg = sprintf("Container '%s' in '%s' '%s' must have runAsUser defined.", [c.name,input.kind,input.metadata.name])
}

# Warn about ReadOnlyRootFilesystem
warn_container_readOnlyRootFilesystem[msg] {
  input.kind == kubernetes.inputs[_]
  some c
  kubernetes.containers[c]
  read_only_root_fs := c.securityContext.readOnlyRootFilesystem
  not read_only_root_fs
  msg = sprintf("Container '%s' in '%s' '%s' should have readOnlyRootFilesystem set to 'true'.", [c.name,input.kind,input.metadata.name])
}
