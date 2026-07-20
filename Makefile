# main.sh test harness — see test/README.md for the contract.
# bats-core and its helper libs are vendored as git submodules under test/lib/;
# nothing is installed at runtime. Run `git submodule update --init --recursive`
# after a fresh clone.

BATS  := ./test/lib/bats-core/bin/bats
TIERS := test/unit test/smoke

.DEFAULT_GOAL := help

.PHONY: help test test-unit test-smoke lint

help: ## List the available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

test: ## Run every tier (unit + smoke), scoped to the tier dirs
	$(BATS) --recursive $(TIERS)

test-unit: ## Run the unit tier (pure functions, no I/O)
	$(BATS) --recursive test/unit

test-smoke: ## Run the smoke tier (subprocess CLI-contract)
	$(BATS) --recursive test/smoke

SHELL_SOURCES := main.sh test/mocks/bin/* test/helpers/*.bash

lint: ## shellcheck correctness + modern-idiom gate (config in .shellcheckrc)
	# General correctness (warnings and up); SC2034 is disabled in .shellcheckrc.
	shellcheck --severity=warning main.sh
	shellcheck test/mocks/bin/*
	shellcheck test/helpers/*.bash
	# Idiom gate: enforce [[ ]] over [ ] (SC2292) and command substitution over
	# backticks (SC2006) across every shell source, regardless of severity.
	shellcheck --include=SC2292,SC2006 $(SHELL_SOURCES)
