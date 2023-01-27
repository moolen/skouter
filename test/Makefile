export ACK_GINKGO_DEPRECATIONS=2.7.0

REPEAT ?= 0
GINKGO_ARGS ?=
VERSION ?= dev

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

all: cluster build deploy test ## bootstrap cluster, deploy app and run all tests
dev: build deploy test ## build & deploy changes and run tests

clean: ## cleans the node-local ebpf state and restart skouter pods
	kubectl delete po -l app=skouter

cluster: ## starts a cluster
	@echo starting cluster
	kind create cluster --config ./kind.yaml

build: ## build+load image
	$(MAKE) -C ../ docker.build IMAGE_TAG=$(VERSION)
	kind load docker-image ghcr.io/moolen/skouter:$(VERSION)

deploy: ## deploy workload and ensure it uses the latest image
	@echo installing skouter
	helm upgrade --install skouter ../deploy/skouter \
		--wait \
		--set image.tag=$(VERSION)
	kubectl delete po -l app=skouter

run: ## run tests against current kubernetes cluster with skouter installed
	ginkgo run -v --repeat=$(REPEAT) $(GINKGO_ARGS) ./suite -- $(TEST_ARGS)


