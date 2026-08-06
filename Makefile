BINARY      ?= tlsa-dnsendpoint-controller
IMAGE       ?= ghcr.io/oscrx/tlsa-dnsendpoint-controller
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PLATFORMS   ?= linux/amd64,linux/arm64

LDFLAGS := -s -w

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_.-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the binary for the host platform
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o build/$(BINARY) .

.PHONY: test
test: ## Run tests with race detection
	go test -race -count=1 ./...

.PHONY: cover
cover: ## Run tests and report coverage
	go test -race -count=1 -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

.PHONY: fmt
fmt: ## Format the code
	gofmt -l -s -w .

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run --timeout=5m ./...

.PHONY: verify
verify: vet lint test chart.verify ## Everything CI runs

.PHONY: image
image: ## Build a single-platform image for the host
	docker build -t $(IMAGE):$(VERSION) .

.PHONY: image.multiarch
image.multiarch: ## Build and push a multi-platform image
	docker buildx build --platform=$(PLATFORMS) -t $(IMAGE):$(VERSION) --push .

.PHONY: manifests
manifests: ## Print the deployment manifests
	@cat deploy/rbac.yaml deploy/deployment.yaml

.PHONY: clean
clean: ## Remove build artefacts
	rm -rf build coverage.out

CHART       ?= charts/tlsa-dnsendpoint-controller
CHART_REPO  ?= oci://ghcr.io/oscrx/charts

.PHONY: chart.lint
chart.lint: ## Lint the Helm chart
	helm lint $(CHART)

.PHONY: chart.template
chart.template: ## Render the chart with default values
	helm template tlsa $(CHART)

.PHONY: chart.verify
chart.verify: chart.lint ## Lint, render and schema-validate the chart
	helm template tlsa $(CHART) | kubeconform -strict -summary -ignore-missing-schemas \
		-schema-location default \
		-schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json' -
	helm template tlsa $(CHART) --set replicaCount=2 --set leaderElection.enabled=true \
		--set metrics.service.enabled=true --set metrics.serviceMonitor.enabled=true \
		| kubeconform -strict -summary -ignore-missing-schemas \
			-schema-location default \
			-schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json' -

.PHONY: chart.package
chart.package: ## Package the chart into dist/
	helm package $(CHART) --destination dist
