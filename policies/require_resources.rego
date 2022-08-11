package kubernetes.requireResources

import data.lib.kubernetes

## Container Resource Requirements
# Required resource definition for all containers
deny_missing_resources[msg] {
  input.kind == kubernetes.inputs[_]
  c := kubernetes.containers[_]
  kubernetes.resources(c)
  msg := sprintf("Container '%s' in '%s' '%s' is missing resources definitions.", [c.name, input.kind, input.metadata.name])
}

warn_resource_limits[msg] {
  input.kind == kubernetes.inputs[_]
  c := kubernetes.containers[_]
  kubernetes.resources_limits(c)
  msg := sprintf("Container '%s' in '%s' '%s' is missing resources.limits definitions.", [c.name, input.kind, input.metadata.name])
}

deny_resource_requests[msg] {
  input.kind == kubernetes.inputs[_]
  c := kubernetes.containers[_]
  kubernetes.resources_requests(c)
  msg := sprintf("Container '%s' in '%s' '%s' is missing resources.requests definitions.", [c.name, input.kind, input.metadata.name])
}
