IMAGE     ?= fabiocicerchia/rbac-auditor
VERSION   ?= 0.1.0
PLATFORMS ?= linux/amd64,linux/arm64

.PHONY: build lint test push release help

.DEFAULT_GOAL := help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  %-10s %s\n", $$1, $$2}'

build: ## Build the image locally
	docker build -t $(IMAGE):$(VERSION) .

lint: ## Lint the Dockerfile and shell scripts
	docker run --rm -i hadolint/hadolint < Dockerfile
	python3 -m py_compile rbac_audit.py

test: build ## Build, then run the smoke tests
	./test.sh $(IMAGE):$(VERSION)

push: build ## Push the tagged image
	docker push $(IMAGE):$(VERSION)

release: ## Multi-arch buildx build and push (version + latest)
	docker buildx build --platform $(PLATFORMS) \
		-t $(IMAGE):$(VERSION) -t $(IMAGE):latest --push .
