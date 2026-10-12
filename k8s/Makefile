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

secret: ## Create the SG credentials Secret from .env
	@test -f .env || { echo "Copy .env.example to .env and fill it in first."; exit 1; }
	kubectl --context $(CONTEXT) apply -f manifests/namespace.yaml
	$(KUBECTL) create secret generic sg-runner-credentials --from-env-file=.env \
		--dry-run=client -o yaml | $(KUBECTL) apply -f -

up: ## Deploy the runner StatefulSet (registers on first start)
	kubectl --context $(CONTEXT) apply -f manifests/

status: ## Show pod, container states and agent health
	$(KUBECTL) get pods,pvc -o wide
	-$(KUBECTL) exec $(POD) -c ecs-agent -- curl -fsS localhost:51678/v1/metadata

logs: ## Tail all runner containers
	$(KUBECTL) logs $(POD) --all-containers --prefix -f --max-log-requests 10

deregister: ## Deregister from SG and wipe local identity (reads .env on stdin)
	$(KUBECTL) exec -i $(POD) -c ecs-agent -- /opt/sg-runner/runner.sh deregister < .env

down: ## Delete the StatefulSet, keep PVCs (runner identity survives)
	-$(KUBECTL) delete statefulset sg-runner

# deregister runs first and aborts nuke on failure, so a runner is never
# orphaned by deleting its identity.
nuke: deregister down ## Deregister, then delete everything including PVCs
	-$(KUBECTL) delete pvc --all
	-kubectl --context $(CONTEXT) delete namespace $(NS)
