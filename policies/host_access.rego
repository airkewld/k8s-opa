package kubernetes.hostAccess

import data.lib.kubernetes

# Warn against hostNetwork and hostPID and hostIPC
warn_host_namespace_access[msg] {
  kubernetes.not_whitelisted_proj
  c := kubernetes.pod[_]
  kubernetes.host_access(c)
  msg = sprintf("Container '%s' in '%s' '%s' requires host access.", [c.containers[_].name, input.kind, input.metadata.name])
}

warn_host_fs_access[msg] {
  kubernetes.not_whitelisted_proj
  c := kubernetes.pod[_]
  kubernetes.host_fs_access(c)
  msg = sprintf("Container '%s' in '%s' '%s' is attempting to mount hostPath %s.", [c.containers[_].name, input.kind, input.metadata.name, c.volumes[_].hostPath])
}
