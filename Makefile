IMAGE     ?= fabiocicerchia/rbac-auditor
VERSION   ?= 0.1.0
PLATFORMS ?= linux/amd64,linux/arm64

.PHONY: build lint test push release

build:
	docker build -t $(IMAGE):$(VERSION) .

lint:
	docker run --rm -i hadolint/hadolint < Dockerfile
	python3 -m py_compile rbac_audit.py

test: build
	./test.sh $(IMAGE):$(VERSION)

push: build
	docker push $(IMAGE):$(VERSION)

release:
	docker buildx build --platform $(PLATFORMS) \
		-t $(IMAGE):$(VERSION) -t $(IMAGE):latest --push .
