# k8s-opa
Opinionated collection of rego policies to check for kubernetes manifest best practices

## Docker image

The docker container contains the most recent version of [conftest](https://www.conftest.dev/) as well as the policies at `/policies`.

## Using locally
```
cat demo/bad-k8s.yaml| docker run --rm -i ttl.sh/k8s-opa -
```
```
docker run --rm -i -v $(pwd):/tmp ttl.sh/k8s-opa /tmp/demo/bad-k8s.yaml
```

