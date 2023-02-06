IMAGE_REGISTRY ?= ghcr.io
IMAGE_REPO ?= moolen/skouter
IMAGE_TAG ?= dev

CLANG ?= clang
STRIP ?= llvm-strip
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

.PHONY: generate
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate ./...
	go run sigs.k8s.io/controller-tools/cmd/controller-gen object \
		paths="./api/..."

	go run sigs.k8s.io/controller-tools/cmd/controller-gen crd \
		paths="./api/..." \
		output:crd:artifacts:config="crds"
	cp ./crds/* ./deploy/skouter/templates/crds


build: generate
	mkdir -p bin
	CGO_ENABLED=0 go build -ldflags='-extldflags=-static' -o bin/skouter main.go

docker.build:
	docker build -t $(IMAGE_REGISTRY)/$(IMAGE_REPO):$(IMAGE_TAG) .

run: build
	sudo -E ./bin/skouter --kubeconfig ~/.kube/config --node-ip 192.168.178.24 --allowed-dns 8.8.8.8 --allowed-dns 192.168.178.1 --node-name kind-worker --cgroupfs /sys/fs/cgroup --bpffs /sys/fs/bpf -v=2

lint.check: ## Check install of golanci-lint
	@if ! golangci-lint --version > /dev/null 2>&1; then \
		echo -e "\033[0;33mgolangci-lint is not installed: run \`\033[0;32mmake lint.install\033[0m\033[0;33m\` or install it from https://golangci-lint.run\033[0m"; \
		exit 1; \
	fi

lint.install: ## Install golangci-lint to the go bin dir
	@if ! golangci-lint --version > /dev/null 2>&1; then \
		echo "Installing golangci-lint"; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOBIN) v1.49.0; \
	fi

lint: lint.check ## Run golangci-lint
	@if ! golangci-lint run; then \
		echo -e "\033[0;33mgolangci-lint failed: some checks can be fixed with \`\033[0;32mmake fmt\033[0m\033[0;33m\`\033[0m"; \
		exit 1; \
	fi
	@echo Finished linting

.PHONY: example
example: docker.build
	kubectl apply -f ./crds/
	kubectl apply -f ./deploy
	kubectl delete po -l app=skouter
