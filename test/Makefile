export ACK_GINKGO_DEPRECATIONS=2.7.0

REPEAT ?= 1

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'


all: cluster build deploy test ## bootstrap cluster, deploy app and run all tests
dev: build deploy test ## build & deploy changes and run tests

clean: ## cleans the node-local ebpf state and restart skouter pods
	minikube ssh "sudo rm -rf /sys/fs/bpf/skouter"
	kubectl delete po -l app=skouter

cluster: ## starts a minikube cluster
	@echo starting cluster
	minikube start

build: ## set minikube docker-env and build image
	eval $(minikube -p minikube docker-env)
	$(MAKE) -C ../ docker.build

deploy: ## deploy workload and ensure it uses the latest image
	@echo installing skouter
	helm upgrade --install --wait skouter ../deploy/skouter
	kubectl delete po -l app=skouter

test: ## run tests against current kubernetes cluster with skouter installed
	ginkgo run -v --repeat=$(REPEAT) ./suite -- $(GINKGO_TEST_ARGS)


