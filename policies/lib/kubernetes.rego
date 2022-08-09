package lib.kubernetes

## manifest types that will be processed
inputs := [
  "DaemonSet",
  "Deployment",
  "ReplicaSet",
  "StatefulSet",
  "Job",
  "CronJob",
]

blacklisted_image_tags := ["latest"]

whitelisted_projects := [
]

forbidden_uids := 0

## vars
name := input.metadata.name

kind := input.kind

## has_field returns whether an object has a field
has_field(object, field) {
  object[field]
}

pod[c] {
  c := input.spec.template.spec
}

containers[c] {
  some i
  c := input.spec.template.spec.initContainers[i]
}

containers[c] {
  some i
  c := input.spec.template.spec.containers[i]
}

containers[c] {
  some i
  c := input.spec.jobTemplate.spec.template.spec.containers[i]
}

containers[c] {
  some i
  c := input.spec.jobTemplate.spec.template.spec.initContainers[i]
}

host_access(c) {
  c.hostNetwork
}

host_access(c) {
  c.hostPID
}

host_access(c) {
  c.hostIPC
}

host_access(c) {
  c.hostNetwork
}

host_fs_access(c) {
  some i
  c.volumes[i].hostPath
}

resources(c) {
  not has_field(c, "resources")
}

resources_limits(c) {
  not c.resources.limits.cpu
}

resources_limits(c) {
  not c.resources.limits.memory
}

resources_requests(c) {
  not c.resources.requests.cpu
}

resources_requests(c) {
  not c.resources.requests.memory
}

deprecated_serviceAccount(c) {
  has_field(c, "serviceAccount")
}

require_serviceAccountName(c) {
  not c.serviceAccountName
}

security_context_requirement(c) {
  not has_field(c, "securityContext")
}

read_only_root_fs(c) {
  c.securityContext.readOnlyRootFilesystem != true
}

prohibit_privilege_escalation(c) {
  c.securityContext.allowPrivilegeEscalation
}

prohibit_privilege_escalation(c) {
  c.securityContext.privileged
}

run_as_user(c) {
  c.securityContext.runAsUser
}

seccomp_profile(c) {
  c.securityContext.seccompProfile
}

seccomp_profile_type(c) {
  not has_field(c.securityContext.seccompProfile.type, "Localhost")
}

any_whitelisted_proj {
  some i
  proj := whitelisted_projects[i]
  proj == name
}

not_whitelisted_proj {
  not any_whitelisted_proj
}

required_labels {
  input.spec.template.metadata.labels.app
}

required_labels {
  input.spec.jobTemplate.metadata.labels.app
}
