package kubernetes.requiredLabels

import data.lib.kubernetes


deny_app_label[msg] {
  input.kind == kubernetes.inputs[_]
  not kubernetes.required_labels
  msg = sprintf("'%s' '%s' must provide an 'app' label.", [input.kind, input.metadata.name])
}
