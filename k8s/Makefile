# sg-runner Kubernetes prototype. Run from k8s/.
# Every kubectl call is pinned to CONTEXT so this never touches a real cluster
# by accident.

CONTEXT ?= orbstack
IMAGE   ?= sg-runner-k8s:dev
NS      := sg-runner
# Release name = chart name, so the StatefulSet (and its pods and PVCs) is
# named sg-runner too.
RELEASE := sg-runner
STS     := $(RELEASE)
POD     := $(STS)-0
CHART   := chart/sg-runner
SECRET  := sg-runner-credentials
KUBECTL := kubectl --context $(CONTEXT) -n $(NS)
HELM    := helm --kube-context $(CONTEXT) -n $(NS)

# build-multiarch: builds every platform and keeps only the build cache unless
# PUSH=1, which pushes $(REGISTRY)/$(IMAGE) (REGISTRY required). The default
# docker driver can't build multi-platform without the containerd image store,
# so it runs on its own docker-container builder, created on first use and
# never made the default.
PLATFORMS ?= linux/amd64,linux/arm64
BUILDER   ?= sg-runner-multiarch
PUSH      ?= 0
REGISTRY  ?=

.DEFAULT_GOAL := help

.PHONY: help build build-multiarch secret up status logs down nuke

help: ## List the available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

build: ## Build the runner image (OrbStack k8s uses local images directly)
	docker build -f Dockerfile -t $(IMAGE) ..

build-multiarch: ## Build amd64 + arm64 (PLATFORMS); cache only, or PUSH=1 REGISTRY=... to push
ifeq ($(PUSH),1)
	@test -n "$(REGISTRY)" || { echo "PUSH=1 needs REGISTRY=<registry/namespace>."; exit 1; }
endif
	@docker buildx inspect $(BUILDER) >/dev/null 2>&1 \
		|| docker buildx create --name $(BUILDER) --driver docker-container
ifeq ($(PUSH),1)
	docker buildx build --builder $(BUILDER) -f Dockerfile --platform $(PLATFORMS) \
		-t $(REGISTRY)/$(IMAGE) --push ..
else
	docker buildx build --builder $(BUILDER) -f Dockerfile --platform $(PLATFORMS) \
		--output type=cacheonly ..
endif

# The scaler (Go, k8s/scaler). SCALER_PLATFORMS builds a multi-arch image instead
# (buildx, e.g. SCALER_PLATFORMS=linux/amd64,linux/arm64 with --push in SCALER_BUILDX_FLAGS).
SCALER_BUILD_IMAGE ?= sg-runner-scaler:dev
SCALER_PLATFORMS ?=
SCALER_BUILDX_FLAGS ?=
.PHONY: build-scaler
build-scaler: ## Build the scaler image (Go)
ifeq ($(SCALER_PLATFORMS),)
	docker build -t $(SCALER_BUILD_IMAGE) scaler
else
	docker buildx build --platform $(SCALER_PLATFORMS) $(SCALER_BUILDX_FLAGS) -t $(SCALER_BUILD_IMAGE) scaler
endif

# The namespace must allow privileged pods (dockerd); the chart doesn't create it.
# Only the node token goes in the Secret; `up` passes the runner group (not
# secret) as chart values, which the chart puts in a ConfigMap.
secret: ## Create the namespace and the node token Secret from .env
	@test -f .env || { echo "Copy .env.example to .env and fill it in first."; exit 1; }
	kubectl --context $(CONTEXT) create namespace $(NS) --dry-run=client -o yaml \
		| kubectl --context $(CONTEXT) apply -f -
	kubectl --context $(CONTEXT) label namespace $(NS) --overwrite \
		pod-security.kubernetes.io/enforce=privileged
	grep '^SG_NODE_TOKEN=' .env \
		| $(KUBECTL) create secret generic $(SECRET) --from-env-file=/dev/stdin \
			--dry-run=client -o yaml | $(KUBECTL) apply -f -

# IMAGE is split into repository and tag for the chart.
up: ## Install or upgrade the chart (registers on first start)
	@test -f .env || { echo "Copy .env.example to .env and fill it in first."; exit 1; }
	. ./.env && $(HELM) upgrade --install $(RELEASE) $(CHART) \
		--set credentials.existingSecret=$(SECRET) \
		--set-string sg.organization="$$SG_ORGANIZATION" \
		--set-string sg.runnerGroup="$$SG_RUNNER_GROUP" \
		--set-string sg.apiUrl="$${SG_BASE_API:-}" \
		--set image.repository=$(firstword $(subst :, ,$(IMAGE))) \
		--set image.tag=$(lastword $(subst :, ,$(IMAGE)))

status: ## Show runner pods and state PVCs (a PVC without a pod is a parked runner)
	$(KUBECTL) get statefulset,deployment,pods,pvc -o wide
	-$(KUBECTL) exec $(POD) -c ecs-agent -- curl -fsS localhost:51678/v1/metadata

logs: ## Tail all runner containers
	$(KUBECTL) logs $(POD) --all-containers --prefix -f --max-log-requests 10

# --no-hooks skips the chart's uninstall cleanup: the runners' PVCs aren't
# part of the release, so every runner parks (drain on the way out) and stays
# registered in SG. With the scaler gone nothing reaps them; `make up` wakes
# them again.
down: ## Uninstall the chart, keep PVCs (runners stay registered, parked)
	-$(HELM) uninstall $(RELEASE) --no-hooks

# The chart's pre-delete hook parks every runner, deregisters each from SG
# and deletes their PVCs; it fails (and the release stays) rather than orphan
# a runner. The timeout covers running workflows.
nuke: ## Uninstall: deregister every runner, delete PVCs, then the namespace
	$(HELM) uninstall $(RELEASE) --timeout 30m
	-kubectl --context $(CONTEXT) delete namespace $(NS)
