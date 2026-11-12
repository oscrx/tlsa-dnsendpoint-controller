# Pipeline

Two workflows: [`ci.yaml`](workflows/ci.yaml) checks every change, and [`release.yaml`](workflows/release.yaml) publishes.

## CI

Runs on every push and pull request to `main`. All jobs run in parallel and are independent of each other. A newer push to the same ref cancels the run in progress.

```mermaid
flowchart LR
    trigger(["Push / PR → main"])

    trigger --> test["<b>Test</b><br/>toolchain check, go mod tidy,<br/>gofmt, vet, go test -race"]
    trigger --> lint["<b>Lint</b><br/>golangci-lint v2.15"]
    trigger --> audit["<b>Audit workflows</b><br/>zizmor → SARIF"]
    trigger --> build["<b>Build image</b><br/>amd64 + arm64, no push"]
    trigger --> renovate["<b>Renovate config</b><br/>validator --strict"]
    trigger --> manifests["<b>Manifests</b><br/>kubeconform on deploy/, examples/"]
    trigger --> chart["<b>Chart</b><br/>helm lint, template,<br/>guard checks"]
```

## Release

Runs on a `v*` tag, or by hand through `workflow_dispatch`. The jobs run one after another. The chart pins the image by digest, and that digest only exists once the image has been pushed. The GitHub release comes last, so the release page only appears once everything it points to exists.

```mermaid
flowchart TD
    tag(["Tag v*"])
    dispatch(["workflow_dispatch"])

    tag --> image
    dispatch --> image

    image["<b>Build and push image</b><br/>go test -race, multi-arch build,<br/>push to ghcr.io with SBOM + provenance,<br/>cosign keyless signature"]
    image -- "tags only" --> chart["<b>Package and push chart</b><br/>pin image digest, check Chart.yaml<br/>version matches tag, push OCI chart,<br/>cosign signature"]
    chart --> release["<b>GitHub release</b><br/>generated release notes"]
```

A manual dispatch only publishes the image, under the moving `:main` tag. A chart version and a GitHub release are only created for a `v*` tag.
