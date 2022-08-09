package kubernetes.serviceAccounts

import data.lib.kubernetes

## Require unique (non default) service account
deny[msg] {
  input.kind == kubernetes.inputs[_]
  service_account := input.spec.template.spec.serviceAccountName
  service_account == "default"
  msg := sprintf("'%s' '%s' is not allowed to use the '%s' serviceAccount.", [input.kind, input.metadata.name, service_account])
}

## Don't use the deprecated serviceAccount field
deny[msg] {
  input.kind == kubernetes.inputs[_]
  c := kubernetes.pod[_]
  kubernetes.deprecated_serviceAccount(c)
  msg := sprintf("'%s' '%s' uses serviceAccount which is deprecated. Please use serviceAccountName instead.", [input.kind, input.metadata.name])
}

## serviceAccountName must be defined
deny[msg] {
  input.kind == kubernetes.inputs[_]
  c := kubernetes.pod[_]
  kubernetes.require_serviceAccountName(c)
  msg := sprintf("'%s' '%s' requires the serviceAccountName to be defined.", [input.kind, input.metadata.name])
}
