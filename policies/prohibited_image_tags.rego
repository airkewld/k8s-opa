package kubernetes.imageTags

import data.lib.kubernetes

## Latest tag
warn_latest_disallowed[msg] {
    input.kind == kubernetes.inputs[_]
    some c
    kubernetes.containers[c]
    val := split(c.image, ":")
    contains(kubernetes.blacklisted_image_tags[_], lower(val[_]))
    msg = sprintf("Container '%s' in '%s' '%s' is trying to use the tag '%v'.", [c.name, input.kind, input.metadata.name, val])
}

## No tag (defaults to latest)
warn_missing_tag[msg] {
    input.kind == kubernetes.inputs[_]
    some c
    kubernetes.containers[c]
    val := split(c.image, ":")
    not val[1]
    msg = sprintf("Container '%s' in '%s' '%s' does not have an image tag.", [c.name, input.kind, input.metadata.name])
}
