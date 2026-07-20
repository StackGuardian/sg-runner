# main.sh test harness — see test/README.md for the contract.
# bats-core and its helper libs are vendored as git submodules under test/lib/;
# nothing is installed at runtime. Run `git submodule update --init --recursive`
# after a fresh clone.

BATS  := ./test/lib/bats-core/bin/bats
TIERS := test/unit test/smoke test/integration

# Integration image: Debian + bash 5 + the mock stubs, with /run/systemd/system
# present so preflight() passes. See test/integration/README.md.
ITEST_IMAGE      := sg-runner-itest
ITEST_DOCKERFILE := test/integration/Dockerfile

.DEFAULT_GOAL := help

.PHONY: help test test-unit test-smoke test-integration test-docker lint

help: ## List the available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

test: ## Run every tier (unit + smoke + integration), scoped to the three tier dirs
	$(BATS) --recursive $(TIERS)

test-unit: ## Run the unit tier (pure functions, no I/O)
	$(BATS) --recursive test/unit

test-smoke: ## Run the smoke tier (subprocess CLI-contract)
	$(BATS) --recursive test/smoke

test-integration: ## Run the integration tier on the host (scaffold; heavy flows skip off-container)
	$(BATS) --recursive test/integration

test-docker: ## Build the integration image and run the integration tier inside it
	docker build -f $(ITEST_DOCKERFILE) -t $(ITEST_IMAGE) .
	docker run --rm $(ITEST_IMAGE)

lint: ## shellcheck main.sh, the mock stubs, and the bash helpers
	shellcheck --severity=warning -e SC2034 main.sh
	shellcheck test/mocks/bin/*
	shellcheck test/helpers/*.bash
