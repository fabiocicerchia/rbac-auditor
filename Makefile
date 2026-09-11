IMAGE     ?= fabiocicerchia/rbac-auditor
VERSION   ?= 0.1.0
PLATFORMS ?= linux/amd64,linux/arm64
# Subcommand for `make run`: snapshot, or diff <file> [<file>]
ARGS      ?= snapshot

# Every verb this repository exposes lives here; `make` on its own prints them.
# FC-GEN-057: the same eight verbs in every repo, each either wired or a
# declared no-op that says why. None of them exit 0 quietly.

.PHONY: help setup install build run test lint format analyze push release

.DEFAULT_GOAL := help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-10s %s\n", $$1, $$2}'

setup: ## Install the pre-commit hook
	pre-commit install

install: ## Install the package (and its man page) with pip
	pip install .

build: ## Build the image locally
	docker build -t $(IMAGE):$(VERSION) .

# Read-only mount of your kubeconfig, and the container runs as you: the tool
# only ever reads RBAC, and nothing it writes should land as root.
run: build ## Snapshot the cluster in your kubeconfig (ARGS=snapshot by default)
	docker run --rm --user "$(shell id -u):$(shell id -g)" \
		-v $(HOME)/.kube/config:/kubeconfig:ro -e KUBECONFIG=/kubeconfig \
		$(IMAGE):$(VERSION) $(ARGS)

# Unit tests first: they need no Docker and no cluster, so a logic error
# fails in seconds rather than after an image build.
test: build ## Build, then run the unit tests and the smoke tests
	python3 -m unittest discover -s tests
	./test.sh $(IMAGE):$(VERSION)

lint: ## Run the whole gate — every hook, every file
	pre-commit run --all-files

format: ## Format the Python with ruff, the formatter the gate checks
	ruff format .

analyze: ## Scan the tree the way CI does — vulnerabilities, misconfig, secrets
	@command -v trivy >/dev/null 2>&1 || { \
		echo "analyze needs trivy: https://trivy.dev/latest/getting-started/installation/" >&2; \
		exit 69; }
	trivy fs --scanners vuln,misconfig,secret --severity CRITICAL,HIGH .

push: build ## Push the tagged image
	docker push $(IMAGE):$(VERSION)

release: ## Multi-arch buildx build and push (version + latest)
	docker buildx build --platform $(PLATFORMS) \
		-t $(IMAGE):$(VERSION) -t $(IMAGE):latest --push .
