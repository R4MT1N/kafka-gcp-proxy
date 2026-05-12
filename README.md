# kafka-gcp-proxy

A minimal sidecar that lets unmodified Kafka clients connect to **GCP Managed Service for Apache Kafka** over plain
`127.0.0.1:9092` while the proxy transparently handles SASL/OAUTHBEARER + TLS to the real brokers.

The Google OAuth access token (scope `cloud-platform`) is sourced from Application Default Credentials —
typically via Workload Identity in GKE or `gcloud auth application-default login` locally. Clients see a normal,
unauthenticated Kafka cluster; no code or config changes needed when migrating from Confluent Cloud or any other
SASL-authenticated cluster.

## Credit

This project is a heavily stripped fork of [grepplabs/kafka-proxy](https://github.com/grepplabs/kafka-proxy),
which inspired the whole approach. All Kafka protocol parsing and the broker-address rewriting machinery come from
that project. Everything not needed for the GCP-Managed-Kafka use case has been removed: gRPC plugin runtime,
listener TLS, local/gateway auth, GSSAPI/AWS_MSK_IAM/PLAIN/SCRAM, JAAS, SOCKS5 forward proxy, and other plugin
binaries. What remains is one binary with one auth mechanism.

## Usage

```bash
kafka-gcp-proxy server \
  --bootstrap-server-mapping "bootstrap.<cluster>.<region>.managedkafka.<project>.cloud.goog:9092,127.0.0.1:9092" \
  --dynamic-listeners-disable
```

Clients then connect to `127.0.0.1:9092` with no SASL/TLS configuration.

### Defaults

The defaults are tuned for GCP Managed Kafka:

- `--tls-enable=true` (required by Managed Kafka)
- `--tls-system-cert-pool=true`
- `--token-provider=google-access-token-provider`
- `--token-provider-param=--adc=true`

To use a service account JSON file instead of ADC:

```bash
--token-provider-param=--adc=false \
--token-provider-param=--credentials-file=/path/to/sa.json
```

## Build

```bash
make build           # local binary in build/
make docker.build    # local Docker image
```

## License

Apache 2.0 — same as the upstream project.
