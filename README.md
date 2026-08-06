# tlsa-dnsendpoint-controller

Publishes TLSA (DANE, RFC 6698) records for cert-manager Certificates by writing
external-dns `DNSEndpoint` resources.

This is the division of labour that neither project does alone: cert-manager owns
the certificate lifecycle but has no way to write DNS records outside ACME
challenges, and external-dns owns ~50 DNS providers but cannot derive a record's
contents from certificate material. This controller sits between them.

```
Certificate ──> [this controller] ──> DNSEndpoint ──> external-dns ──> your DNS provider
   (cert-manager)                       (crd source)
```

Related upstream discussion: [cert-manager#6472](https://github.com/cert-manager/cert-manager/issues/6472).

## What it does

For a Certificate that opts in via annotations, it maintains a single
`DNSEndpoint` named `<certificate-name>-tlsa` in the same namespace, holding one
TLSA record per (DNS name × port).

The `DNSEndpoint` carries an owner reference to the Certificate. That is a
deliberate design choice: **no finalizer is involved anywhere**, so deleting a
Certificate can never block on DNS being reachable — Kubernetes garbage
collection removes the `DNSEndpoint`, and external-dns withdraws the records on
its next sync.

## Renewal safety

Naively replacing a TLSA record when a certificate is renewed breaks DANE. RFC
7671 section 8.1 requires the new record to be published *before* the new
certificate is served, and both to coexist during the changeover. This matters
more than it used to: cert-manager's `privateKey.rotationPolicy` now defaults to
`Always`, so the key — and therefore the SPKI digest — changes on **every**
renewal.

This controller handles both ends of the window:

**Before issuance — pre-publication.** cert-manager writes the next private key
to its own Secret and sets `status.nextPrivateKeySecretName` *before* it requests
the new certificate. With the default `SPKI` selector, the record data depends
only on the public key, so the digest for the not-yet-issued certificate is
already knowable. This controller reads that key and publishes its record
alongside the current one, so by the time the new certificate is served, a
matching TLSA record has already been in DNS for the whole issuance round trip.

This is impossible with `selector: FullCert`, where the digest covers fields the
CA fills in at signing time. That is the main reason to stay on `SPKI`.

**After issuance — retirement.** The superseded digest stays published for
`--rollover-grace` (default 168h) rather than being deleted immediately. The
controller cannot observe when your server actually stops presenting the old
certificate — that depends on whether the workload reloads, and when. Publishing
an extra TLSA record is harmless: DANE succeeds if *any* record matches.
Removing one too early is what breaks validation. So the default errs long.
Retirement state is tracked in an annotation on the `DNSEndpoint`.

## Requirements

- cert-manager, any recent version.
- external-dns running with `--source=crd` and `--managed-record-types=TLSA`.
  The default managed set is A/AAAA/CNAME only, so **TLSA records are silently
  ignored without that flag**.
- The external-dns `DNSEndpoint` CRD installed:
  `kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/external-dns/master/config/crd/standard/dnsendpoints.externaldns.k8s.io.yaml`
- **A DNS provider whose external-dns implementation reads TLSA records back.**
  See the caveat below — this is the part most likely to bite you.
- DNSSEC on the zone. Without it, DANE offers nothing; nothing here checks.

### Ownership does not round-trip (all providers)

Before any provider-specific concern: external-dns's TXT registry will create an
ownership record for a TLSA endpoint but will not recognise it again.

`registry/mapper` writes the ownership TXT generically — `ToTXTName` yields
`tlsa-_443._tcp.example.com` with no changes needed. But the reverse direction,
`ToEndpointName` → `dropAffixExtractType` → `extractRecordTypeDefaultPosition`,
matches the leading token against a hardcoded `supportedRecords` list that omits
TLSA. Round-tripping `tlsa-_443._tcp.example.com` returns the name unstripped and
an empty record type:

```
A     write=a-_443._tcp.example.com      read back  name="_443._tcp.example.com"      type="A"
SRV   write=srv-_443._tcp.example.com    read back  name="_443._tcp.example.com"      type="SRV"
TLSA  write=tlsa-_443._tcp.example.com   read back  name="tlsa-_443._tcp.example.com" type=""
```

The consequence is the failure mode described in
[external-dns#6180](https://github.com/kubernetes-sigs/external-dns/issues/6180):
records get created, external-dns never acknowledges ownership of them, and it
therefore never updates or deletes them. Adding TLSA to `supportedRecords` in
`registry/mapper/mapper.go` fixes it — one line, and it applies to every provider,
not just Cloudflare.

### The provider caveat

TLSA is also not in external-dns's supported record types, and what that costs
you depends on the provider.

`provider/recordfilter.go` allows only `A, AAAA, CNAME, SRV, TXT, NS`. Providers
filter reads through it, so TLSA records are dropped on the way back in. Without
reads, external-dns sees no existing state: it attempts a create on every sync
and never updates or deletes correctly. Write paths vary — rfc2136 formats
presentation syntax and hands it to `dns.NewRR`, so writes work there untouched.

**Cloudflare needs more than a read-path fix.** See the section below.

Verify against your provider before relying on this.

### Cloudflare

Four separate things need attention, and only the last one is handled here.

1. **Reads are filtered.** `groupByNameAndTypeWithCustomHostnames` skips any type
   `SupportedAdditionalRecordTypes` rejects, and that falls through to the shared
   `provider.SupportedRecordType`, which excludes TLSA. Fix: add TLSA there, or
   to Cloudflare's own list next to MX.

2. **Writes need structured `data`, not `content`.** Cloudflare models TLSA like
   SRV: `TLSARecordParam` in cloudflare-go has **no `Content` field at all**,
   only `Data{Usage, Selector, MatchingType, Certificate}`, and the read-side
   `Content` is documented as "Formatted TLSA content. See 'data' to set TLSA
   properties." external-dns already special-cases exactly this for SRV, in
   `buildSRVRecordParam` (batch path) and `getCreateDNSRecordParam` (single
   path). A `buildTLSARecordParam` alongside them, parsing `"3 1 1 <hex>"` into
   the four fields, is the missing piece — SRV is a direct template.

3. **Record identity comes from `Content`.** `newDNSRecordIndex` keys records on
   `endpointTargetFromCloudflareRecord`, which returns `record.Content` for
   everything except SRV, where it re-renders from `Data`. TLSA needs the same
   treatment, otherwise whatever formatting Cloudflare chooses for the rendered
   `content` (hex case, spacing) has to match ours exactly or every sync sees a
   spurious diff and churns.

4. **Proxying.** TLSA is missing from `recordTypeProxyNotSupported`, so with
   `--cloudflare-proxied` external-dns will try to create TLSA records with
   `proxied=true` and Cloudflare will reject them. Work around it from this side:

   ```
   --provider-specific=external-dns.kubernetes.io/cloudflare-proxied=false
   ```

   (Match external-dns's own `--annotation-prefix` if you have changed it.)

Taken together, 1–3 plus the registry fix above are a modest upstream patch
closely modelled on the existing SRV handling. Item 2 is worth writing as a
dispatch keyed on record type rather than a second `if`: thirteen Cloudflare
record types are `data`-only on write (CAA, CERT, DNSKEY, DS, HTTPS, LOC, NAPTR,
SMIMEA, SRV, SSHFP, SVCB, TLSA, URI) and external-dns implements exactly one of
them today.

#### Proxied records make DANE meaningless

Independent of external-dns: if the A/AAAA record for the name is proxied — the
orange cloud — clients complete TLS with **Cloudflare's edge certificate**, not
your origin's. A `DANE-EE` record pinning your cert-manager certificate would
then never match what a client actually sees, and DANE validation fails for
everyone who checks.

- **SMTP (25, 465, 587): fine.** Cloudflare does not proxy SMTP; those names are
  DNS-only and clients reach your MTA directly. This is the case DANE is mostly
  deployed for, and the one this controller is most useful for.
- **HTTPS behind the proxy: do not do this.** Turn the proxy off for that name,
  or do not publish TLSA records for it.

Also: enable DNSSEC on the zone (Cloudflare supports it, but you must add the DS
record at your registrar). Without DNSSEC, TLSA records authenticate nothing.
Nothing here checks that for you.

## Installation

### Helm (recommended)

The chart is published as an OCI artifact:

```bash
helm install tlsa oci://ghcr.io/oscrx/charts/tlsa-dnsendpoint-controller \
  --version 0.1.0 \
  --namespace cert-manager
```

See [charts/tlsa-dnsendpoint-controller](charts/tlsa-dnsendpoint-controller) for
the values. The chart refuses configurations that would misbehave at runtime —
more than one replica without leader election, an empty annotation prefix, a
ServiceMonitor without metrics — rather than letting you discover them from logs.

### Plain manifests

Without Helm:

```bash
kubectl apply -f deploy/rbac.yaml
kubectl apply -f deploy/deployment.yaml
```

These are the minimal equivalent of the chart's defaults, maintained by hand, so
prefer the chart if you want to change anything.

The Deployment references `ghcr.io/oscrx/tlsa-dnsendpoint-controller:0.1.0`,
published multi-arch and cosign-signed by the release workflow. To build locally:

```bash
go build -o tlsa-dnsendpoint-controller .
```

## Configuration

Annotations on the Certificate. Prefix is `tlsa.oscarr.nl` by default; change it
with `--annotation-prefix`.

| Annotation | Default | Meaning |
|---|---|---|
| `enabled` | *(required)* | Must be `"true"`. Nothing happens without it. |
| `ports` | `443` | Comma-separated ports, e.g. `"25,465,587"`. |
| `protocol` | `tcp` | `tcp`, `udp` or `sctp`. |
| `usage` | `DANE-EE` | `PKIX-TA`, `PKIX-EE`, `DANE-TA`, `DANE-EE` (or `0`–`3`). |
| `selector` | `SPKI` | `SPKI` or `FullCert` (or `0`–`1`). |
| `matching-type` | `SHA256` | `SHA256` or `SHA512` (or `1`–`2`). |
| `ttl` | `300` | Record TTL in seconds. |
| `dns-names` | all of `spec.dnsNames` | Restrict which names get records. |

A malformed annotation value is never silently defaulted — the controller emits a
`TLSAConfigInvalid` warning event and publishes nothing, because a typo that
quietly published the wrong digest would be worse than publishing nothing.

Setting `enabled: "false"` after records exist deletes the `DNSEndpoint`,
withdrawing them.

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `--annotation-prefix` | `tlsa.oscarr.nl` | Annotation domain prefix. |
| `--provider-specific` | *(none)* | `key=value` passed to the external-dns provider on every record. Repeatable. See [Cloudflare](#cloudflare). |
| `--rollover-grace` | `168h` | How long a superseded record stays published. |
| `--resync-period` | `1h` | Full reconcile interval absent watch events. |
| `--namespace` | *(all)* | Restrict to one namespace. |
| `--leader-elect` | `false` | Needed only for multiple replicas. |
| `--metrics-bind-address` | `:8080` | `0` to disable. |
| `--health-probe-bind-address` | `:8081` | |

## Example

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: mail
  annotations:
    tlsa.oscarr.nl/enabled: "true"
    tlsa.oscarr.nl/ports: "25,465,587"
spec:
  secretName: mail-tls
  dnsNames: [mail.example.com]
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
```

Produces `_25._tcp.mail.example.com`, `_465._tcp.…` and `_587._tcp.…`, each
`TLSA 3 1 1 <sha256 of the SPKI>`. More in [examples/](examples/).

Verify what landed:

```bash
kubectl get dnsendpoint mail-tlsa -o yaml
dig +dnssec TLSA _25._tcp.mail.example.com
```

## Behaviour notes

- **Wildcard names are skipped** with a `TLSANameSkipped` warning. DANE clients
  look up TLSA records under the concrete name they connected to, so a wildcard
  owner name would never be queried.
- **`DANE-TA`/`PKIX-TA`** use the intermediate from `tls.crt` when the chain has
  one (which is what RFC 7671 section 5.2.2 wants, since that is the certificate
  the peer presents), falling back to `ca.crt`. If neither exists, a
  `TLSADataUnavailable` warning is emitted and nothing is published.
- **`matchingType: Full`** is rejected. It embeds the entire certificate or SPKI
  in DNS, is discouraged by RFC 7671 section 6, and many providers reject the
  resulting rdata length.
- **A missing or unreadable Secret never withdraws existing records.** A
  transient read failure must not break DANE.
- **Record data is lowercase, contiguous hex** with no colons or wrapping, per
  RFC 6698 section 2.2. Some providers reject the alternatives.
- **Secrets are not cached.** They are read directly from the API server, so the
  controller needs only `get` on Secrets and never holds cluster secret material
  in memory. Renewals still reach the controller because cert-manager updates the
  Certificate's status when key material changes.

## Scope

Out of scope, deliberately: DNSSEC signing, SVCB/HTTPS records (RFC 9460),
verifying that published records actually resolve, and any DANE validation of
your own services. Records for names not covered by a cert-manager Certificate
belong in a hand-written `DNSEndpoint`.

## Development

```bash
make verify   # vet, lint and race-enabled tests — what CI runs
make test     # tests only
make lint     # golangci-lint
make build    # binary into build/
make image    # single-platform image for the host
```

CI runs the same checks on every push and pull request, plus a two-platform image
build to catch cross-compilation breakage. Images are published only from
`release.yaml`, on a `v*` tag or a manual dispatch: multi-arch, with provenance,
an SBOM, and a keyless cosign signature.

### Tests

The TLSA digests in `internal/tlsa/testdata` are asserted against values
computed independently with OpenSSL, so the tests are a genuine RFC 6698
conformance check rather than a restatement of the implementation. One test also
feeds the generated rdata through `miekg/dns` — the library external-dns
providers use to build resource records — to confirm the presentation format is
one those providers will accept.

## License

Apache 2.0. See [LICENSE](LICENSE).
