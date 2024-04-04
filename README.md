# trivy-output-plugin-kafka
Trivy plugin output to kafka

## Installation
```shell
trivy plugin install github.com/phankhanhpvk/trivy-plugin-output-to-kafka
```

## Usage

```shell
trivy <target> --format json --output plugin=kafka [--output-plugin-arg plugin_flags] <target_name>
```

OR

```shell
trivy <target> -f json <target_name> | trivy kafka [plugin_flags]
```

## Examples

```shell
trivy image -f json -o plugin=kafka --output-plugin-arg "--topic=trivy" --output-plugin-arg "--topic=localhost:9092" debian:12
```

is equivalent to:

```shell
trivy image -f json debian:12 | trivy kafka --output-plugin-arg "--topic=trivy" --output-plugin-arg "--topic=localhost:9092"
```
