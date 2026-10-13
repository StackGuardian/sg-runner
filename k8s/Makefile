# sg-runner Kubernetes prototype. Run from k8s/.
# Every kubectl call is pinned to CONTEXT so this never touches a real cluster
# by accident.

CONTEXT ?= orbstack
IMAGE   ?= sg-runner-k8s:dev
NS      := sg-runner
POD     := sg-runner-0
KUBECTL := kubectl --context $(CONTEXT) -n $(NS)

.DEFAULT_GOAL := help

.PHONY: help build secret up status logs deregister down nuke

help: ## List the available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

build: ## Build the runner image (OrbStack k8s uses local images directly)
	docker build -f Dockerfile -t $(IMAGE) ..

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

secret: ## Create the SG credentials Secret from .env
	@test -f .env || { echo "Copy .env.example to .env and fill it in first."; exit 1; }
	kubectl --context $(CONTEXT) apply -f manifests/namespace.yaml
	$(KUBECTL) create secret generic sg-runner-credentials --from-env-file=.env \
		--dry-run=client -o yaml | $(KUBECTL) apply -f -

up: ## Deploy the runner StatefulSet (registers on first start)
	kubectl --context $(CONTEXT) apply -f manifests/

status: ## Show runner pods and state PVCs (a PVC without a pod is a parked runner)
	$(KUBECTL) get statefulset,pods,pvc -o wide
	-$(KUBECTL) exec $(POD) -c ecs-agent -- curl -fsS localhost:51678/v1/metadata

logs: ## Tail all runner containers
	$(KUBECTL) logs $(POD) --all-containers --prefix -f --max-log-requests 10

# Parked runners are still registered but have no pod to run from, so wake
# every runner that has a state PVC first, then deregister them one by one.
deregister: ## Wake parked runners, deregister all from SG, wipe identities (reads .env on stdin)
	@n=$$($(KUBECTL) get pvc -o name | grep -c '/state-sg-runner-' || true); \
	if [ "$$n" -eq 0 ]; then echo "No runners to deregister."; exit 0; fi; \
	$(KUBECTL) scale statefulset sg-runner --replicas=$$n && \
	for i in $$(seq 0 $$((n - 1))); do \
		$(KUBECTL) wait --for=condition=Ready pod/sg-runner-$$i --timeout=300s && \
		$(KUBECTL) exec -i sg-runner-$$i -c ecs-agent -- /opt/sg-runner/runner.sh deregister < .env \
			|| exit 1; \
	done

down: ## Delete the StatefulSet, keep PVCs (runner identity survives)
	-$(KUBECTL) delete statefulset sg-runner

# deregister runs first and aborts nuke on failure, so a runner is never
# orphaned by deleting its identity.
nuke: deregister down ## Deregister, then delete everything including PVCs
	-$(KUBECTL) delete pvc --all
	-kubectl --context $(CONTEXT) delete namespace $(NS)
