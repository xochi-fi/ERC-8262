.PHONY: build test test-sol test-noir test-sdk test-xochi-sdk test-all fmt fmt-check lint slither snapshot benchmark fixtures check-toolchain clean help

FOUNDRY_BIN := $(HOME)/.config/.foundry/bin
FORGE := $(FOUNDRY_BIN)/forge
NARGO := nargo
CIRCUITS := compliance risk_score pattern attestation membership non_membership

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ── Build ────────────────────────────────────────────────────

build: build-sol build-noir ## Build everything

build-sol: ## Compile Solidity contracts
	$(FORGE) build

build-noir: ## Compile all Noir circuits
	cd circuits && $(NARGO) compile --workspace

# ── Test ─────────────────────────────────────────────────────

test: test-sol ## Run Solidity tests (default)

test-sol: ## Run Solidity tests (forge test)
	$(FORGE) test

test-sol-v: ## Run Solidity tests verbose
	$(FORGE) test -vvv

test-noir: ## Run all Noir circuit tests
	cd circuits && $(NARGO) test --workspace

test-sdk: ## Run TS consumer SDK tests (noir_js + bb.js + anvil)
	npm run test:sdk

test-xochi-sdk: ## Run @xochi/sdk cross-repo tests (requires ../xochi-sdk)
	npx vitest run --config vitest.cross-repo.config.ts

test-all: test-sol test-noir test-sdk ## Run all tests

# ── Formatting & Lint ────────────────────────────────────────

fmt: ## Format Solidity sources
	$(FORGE) fmt

fmt-check: ## Check Solidity formatting (CI)
	$(FORGE) fmt --check

lint: fmt-check ## Lint (currently fmt-check only)

slither: ## Run Slither static analysis (requires slither-analyzer)
	@mv src/generated /tmp/xochi-generated-backup 2>/dev/null || true
	@slither . || (mv /tmp/xochi-generated-backup src/generated 2>/dev/null; exit 1)
	@mv /tmp/xochi-generated-backup src/generated 2>/dev/null || true

# ── Fixtures & Gas ───────────────────────────────────────────

check-toolchain: ## Verify pinned nargo + bb versions match .tool-versions
	./scripts/check-toolchain.sh

fixtures: check-toolchain ## Generate proof fixtures for all circuits
	./scripts/generate-fixtures.sh

snapshot: ## Capture gas snapshot
	FOUNDRY_PROFILE=default FOUNDRY_FUZZ_SEED=0x1 $(FORGE) snapshot --no-match-contract InvariantTest

benchmark: ## Run gas benchmarks with report
	$(FORGE) test --match-contract GasBenchmark -vvv --gas-report

# ── Clean ────────────────────────────────────────────────────

clean: ## Remove build artifacts
	$(FORGE) clean
	rm -rf node_modules
	@for c in $(CIRCUITS); do \
		rm -rf circuits/$$c/target; \
	done
