.PHONY: build test vet migrate serve docker

BRANCH      := $(shell git rev-parse --abbrev-ref HEAD)
SHA1        := $(shell git rev-parse HEAD)
SHORT_SHA1  := $(shell git rev-parse --short HEAD)
ORIGIN      := $(shell git remote get-url origin)
DATE        := $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
VER         := $(shell git describe --tags --abbrev=0 2>/dev/null || echo "0.0.1")
DOCK_REPO   := docker.patrickdk.com/dswett/debproxy

export DOCKERFILE_PATH=Dockerfile
export DOCKER_REPO=$(DOCK_REPO)
export DOCKER_TAG=latest
export DOCKER_HUB=patrickdk/debproxy
export GIT_BRANCH=$(BRANCH)
export GIT_SHA1=$(SHA1)
export GIT_SHORT_SHA1=$(SHORT_SHA1)
export GIT_TAG=$(SHA1)
export GIT_VERSION=$(VER)
export GIT_VERSION_MAJOR=$(shell echo $(VER) | cut -f1 -d.)
export GIT_VERSION_MINOR=$(shell echo $(VER) | cut -f2 -d.)
export IMAGE_NAME=$(DOCKER_REPO):$(VER)
export SOURCE_BRANCH=$(BRANCH)
export SOURCE_COMMIT=$(SHA1)
export SOURCE_TYPE=git
export SOURCE_REPOSITORY_URL=$(ORIGIN)

BINARY := debproxy
PKG := ./...

all:	buildx

build:
	go build -o $(BINARY) ./cmd/debproxy

test:
	go test $(PKG)

vet:
	go vet $(PKG)

migrate: build
	./$(BINARY) migrate --config config.example.yaml

serve: build
	./$(BINARY) serve --config config.example.yaml

docker:
	docker build -t debproxy .

buildx:
	docker buildx build --pull --push \
		--platform linux/amd64,linux/arm64 \
		--build-arg BUILD_GOOS=linux \
		--build-arg BUILD_DATE=$(DATE) \
		--build-arg BUILD_REF=$(SHORT_SHA1) \
		--build-arg BUILD_VERSION=$(VER) \
		--file $(DOCKERFILE_PATH) \
		--tag $(IMAGE_NAME) \
		.
	skopeo copy --all docker://$(IMAGE_NAME) docker://$(DOCKER_REPO):$(GIT_VERSION_MAJOR)
	skopeo copy --all docker://$(IMAGE_NAME) docker://$(DOCKER_REPO):$(GIT_VERSION_MAJOR).$(GIT_VERSION_MINOR)
	skopeo copy --all docker://$(IMAGE_NAME) docker://$(DOCKER_REPO):latest

	skopeo copy --all docker://$(IMAGE_NAME) docker://$(DOCKER_HUB):$(GIT_VERSION_MAJOR)
	skopeo copy --all docker://$(IMAGE_NAME) docker://$(DOCKER_HUB):$(GIT_VERSION_MAJOR).$(GIT_VERSION_MINOR)
	skopeo copy --all docker://$(IMAGE_NAME) docker://$(DOCKER_HUB):latest
