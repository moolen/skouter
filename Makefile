IMAGE_REGISTRY ?= ghcr.io
IMAGE_REPO ?= moolen/skouter
IMAGE_TAG ?= 0.1.0

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
	sudo -E ./bin/skouter --kubeconfig ~/.kube/config --loglevel debug --node-name minikube --cgroupfs /sys/fs/cgroup

.PHONY: example
example: docker.build
	kubectl apply -f ./crds/
	kubectl apply -f ./deploy
	kubectl delete po -l app=skouter
