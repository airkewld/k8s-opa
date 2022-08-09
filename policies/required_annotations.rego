package kubernetes.requiredAnnotations

import data.lib.kubernetes

# check for annotation value to be localhost
## fix this
warn_apparmor_local_profile[msg] {
    some c
    input.kind == kubernetes.inputs[_]
    annotation := concat("/", ["container.apparmor.security.beta.kubernetes.io", kubernetes.containers[c].name])
    profile := input.spec.template.metadata.annotations[annotation]
    not contains("localhost/", profile)
    msg := sprintf("AppArmor profile '%s' is not allowed on container '%s' on '%s' '%s'.",[profile, kubernetes.containers[c].name, kubernetes.kind, kubernetes.name])
}


warn_missing_apparmor[msg] {
  some c
  annotation := concat("/", ["container.apparmor.security.beta.kubernetes.io", kubernetes.containers[c].name])
  not input.spec.template.metadata.annotations[annotation]
  msg := sprintf("Container '%s' on '%s' '%s' is missing apparmor annotation.", [kubernetes.containers[c].name, kubernetes.kind, kubernetes.name])
}
