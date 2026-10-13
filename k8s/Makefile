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

.DEFAULT_GOAL := help

.PHONY: help build secret up status logs deregister down nuke

help: ## List the available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

build: ## Build the runner image (OrbStack k8s uses local images directly)
	docker build -f Dockerfile -t $(IMAGE) ..

# The namespace must allow privileged pods (dockerd); the chart doesn't create it.
secret: ## Create the namespace and the SG credentials Secret from .env
	@test -f .env || { echo "Copy .env.example to .env and fill it in first."; exit 1; }
	kubectl --context $(CONTEXT) create namespace $(NS) --dry-run=client -o yaml \
		| kubectl --context $(CONTEXT) apply -f -
	kubectl --context $(CONTEXT) label namespace $(NS) --overwrite \
		pod-security.kubernetes.io/enforce=privileged
	$(KUBECTL) create secret generic $(SECRET) --from-env-file=.env \
		--dry-run=client -o yaml | $(KUBECTL) apply -f -

# IMAGE is split into repository and tag for the chart.
up: ## Install or upgrade the chart (registers on first start)
	$(HELM) upgrade --install $(RELEASE) $(CHART) \
		--set credentials.existingSecret=$(SECRET) \
		--set image.repository=$(firstword $(subst :, ,$(IMAGE))) \
		--set image.tag=$(lastword $(subst :, ,$(IMAGE)))

status: ## Show runner pods and state PVCs (a PVC without a pod is a parked runner)
	$(KUBECTL) get statefulset,deployment,pods,pvc -o wide
	-$(KUBECTL) exec $(POD) -c ecs-agent -- curl -fsS localhost:51678/v1/metadata

logs: ## Tail all runner containers
	$(KUBECTL) logs $(POD) --all-containers --prefix -f --max-log-requests 10

# Parked runners are still registered but have no pod to run from, so wake
# every runner that has a state PVC first, then deregister them one by one.
# The scaler is stopped first: it would park the woken runners again.
deregister: ## Wake parked runners, deregister all from SG, wipe identities (reads .env on stdin)
	@n=$$($(KUBECTL) get pvc -o name | grep -c '/state-$(STS)-' || true); \
	if [ "$$n" -eq 0 ]; then echo "No runners to deregister."; exit 0; fi; \
	$(KUBECTL) scale deployment $(STS)-scaler --replicas=0 2>/dev/null; \
	$(KUBECTL) scale statefulset $(STS) --replicas=$$n && \
	for i in $$(seq 0 $$((n - 1))); do \
		$(KUBECTL) wait --for=condition=Ready pod/$(STS)-$$i --timeout=300s && \
		$(KUBECTL) exec -i $(STS)-$$i -c ecs-agent -- /opt/sg-runner/runner.sh deregister < .env \
			|| exit 1; \
	done

# The runners' PVCs aren't part of the release: uninstalling parks every
# runner (drain on the way out) and leaves it registered in SG. With the scaler
# gone nothing reaps them; `make up` wakes them again.
down: ## Uninstall the chart, keep PVCs (runners stay registered, parked)
	-$(HELM) uninstall $(RELEASE)

# deregister runs first and aborts nuke on failure, so a runner is never
# orphaned by deleting its identity.
nuke: deregister down ## Deregister, then uninstall and delete PVCs and namespace
	-$(KUBECTL) delete pvc --all
	-kubectl --context $(CONTEXT) delete namespace $(NS)
