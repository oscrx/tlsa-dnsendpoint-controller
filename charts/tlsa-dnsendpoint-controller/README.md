# tlsa-dnsendpoint-controller

Publishes TLSA (DANE, RFC 6698) records for cert-manager Certificates by
maintaining an external-dns `DNSEndpoint`.

## Install

```sh
helm install tlsa oci://ghcr.io/oscrx/charts/tlsa-dnsendpoint-controller \
  --version 0.2.4 \
  --namespace cert-manager
```

## Requirements

| Component | Required | Notes |
| --- | --- | --- |
| Kubernetes | ≥ 1.25 | Declared as `kubeVersion` in `Chart.yaml`. |
| cert-manager | any recent release | Uses the `cert-manager.io/v1` `Certificate` API. |
| external-dns | **≥ v0.23.0** | TLSA support landed in [external-dns#6616](https://github.com/kubernetes-sigs/external-dns/pull/6616). Earlier versions cannot read TLSA records back, and on Cloudflare reject writes with `usage is a required data field`. |
| `DNSEndpoint` CRD | `externaldns.k8s.io/v1alpha1` | Installed automatically by the official external-dns Helm chart. Other install methods may not — check with `kubectl get crd dnsendpoints.externaldns.k8s.io`. |

external-dns must run with `--source=crd` **and `--managed-record-types=TLSA`**.
TLSA is not in the default managed set, so records are silently ignored without
that flag.

DNSSEC must be enabled on the zone. Without it TLSA records authenticate
nothing; the chart does not check.

See the [project README](https://github.com/oscrx/tlsa-dnsendpoint-controller#provider-support)
for per-provider detail and troubleshooting.

## Usage

Annotate a Certificate to opt it in:

```sh
kubectl annotate certificate mail tlsa.oscarr.nl/enabled=true
```

A `DNSEndpoint` named `<certificate>-tlsa` appears in the same namespace. See
the project README for the full annotation set.

## Values worth knowing

| Key | Default | Notes |
| --- | --- | --- |
| `controller.annotationPrefix` | `tlsa.oscarr.nl` | Becomes part of the annotation key, so set a DNS subdomain you control. |
| `controller.rolloverGrace` | `168h` | How long a superseded record stays published. Errs long on purpose: an extra TLSA record is harmless, removing one too early breaks DANE. |
| `controller.resyncPeriod` | `1h` | Full reconcile interval absent watch events. |
| `controller.namespace` | `""` | Restrict to one namespace. Empty watches all. |
| `controller.providerSpecific` | `[]` | Passed to the external-dns provider. On Cloudflare set `external-dns.kubernetes.io/cloudflare-proxied=false` if external-dns runs with `--cloudflare-proxied`. |
| `replicaCount` | `1` | More than one requires `leaderElection.enabled`; the chart refuses otherwise. |
| `leaderElection.enabled` | `false` | Adds a Role/RoleBinding for the lease. |
| `metrics.enabled` | `true` | Serves metrics on `metrics.port`. |
| `metrics.service.enabled` | `false` | A Service for the metrics port. |
| `metrics.serviceMonitor.enabled` | `false` | Needs the Prometheus Operator CRDs. Implies the Service. |
| `rbac.create` | `true` | Certificates are watched cluster-wide, so the ClusterRole is required unless you manage RBAC yourself. |
| `extraObjects` | `[]` | Rendered through `tpl`, for shipping a Certificate alongside. |

`values.yaml` is commented throughout and is the complete reference.

## Notes on behaviour

The `DNSEndpoint` carries an owner reference rather than a finalizer, so
deleting a Certificate can never block on DNS being reachable — garbage
collection withdraws the records.

On renewal the record for the *next* certificate is published before that
certificate exists, using the next private key cert-manager writes ahead of the
request. That satisfies RFC 7671 section 8.1, and means DANE validation has no
gap across a renewal. Only possible with `selector: SPKI`, which is the default.
