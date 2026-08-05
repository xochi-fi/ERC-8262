.PHONY: build test test-sol test-noir test-sdk test-xochi-sdk test-all fmt fmt-check lint slither snapshot benchmark fixtures check-toolchain parity-check drift-check clean help

FOUNDRY_BIN := $(HOME)/.config/.foundry/bin
FORGE := $(FOUNDRY_BIN)/forge
NARGO := nargo
CIRCUITS := compliance risk_score pattern attestation membership non_membership

# Sibling checkout of ethereum/ERCs, where the submitted copy of the draft and
# its vendored assets live. Optional: drift-check skips those when absent.
ERCS_ROOT ?= ../ERCs
ERCS_DRAFT := $(ERCS_ROOT)/ERCS/erc-8262.md
ERCS_CONTRACTS := $(ERCS_ROOT)/assets/erc-8262/contracts

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

coverage: ## Run forge coverage (summary report; excludes generated/test/script)
	@# Skip ratchet + MAX_BATCH_SIZE gas tests: under --ir-minimum gas inflates
	@# and warp ordering shifts, so these become non-deterministic.
	$(FORGE) coverage \
		--ir-minimum \
		--no-match-test "test_ratchet_acceptsForwardProgression|test_ratchet_rejectsOlderProof|test_ratchet_rejectsBackwardEvenWithinMaxAge|test_ratchet_separateJurisdictions_independent|test_ratchet_separateUsers_independent|test_gas_batch_atMaxSize_fitsBlockGasTarget" \
		--report summary

coverage-lcov: ## Run forge coverage and emit lcov.info
	$(FORGE) coverage \
		--ir-minimum \
		--no-match-test "test_ratchet_acceptsForwardProgression|test_ratchet_rejectsOlderProof|test_ratchet_rejectsBackwardEvenWithinMaxAge|test_ratchet_separateJurisdictions_independent|test_ratchet_separateUsers_independent|test_gas_batch_atMaxSize_fitsBlockGasTarget" \
		--report lcov

# ── Formatting & Lint ────────────────────────────────────────

fmt: ## Format Solidity sources
	$(FORGE) fmt

fmt-check: ## Check Solidity formatting (CI)
	$(FORGE) fmt --check

lint: fmt-check ## Lint (currently fmt-check only)

slither: ## Run Slither static analysis (requires slither-analyzer)
	@mv src/generated /tmp/erc8262-generated-backup 2>/dev/null || true
	@slither . || (mv /tmp/erc8262-generated-backup src/generated 2>/dev/null; exit 1)
	@mv /tmp/erc8262-generated-backup src/generated 2>/dev/null || true

# ── Fixtures & Gas ───────────────────────────────────────────

check-toolchain: ## Verify pinned nargo + bb versions match .tool-versions
	./scripts/check-toolchain.sh

parity-check: ## Verify circuit <-> Solidity public-input arity parity (audit F-8)
	python3 scripts/parity-check.py .

drift-check: ## Verify ERC draft <-> src interfaces and public-input tables (both copies)
	@echo "==> this repository"
	python3 scripts/eip-interface-drift.py .
	python3 scripts/public-input-drift.py .
	@if [ -f "$(ERCS_DRAFT)" ]; then \
	  echo "==> ethereum/ERCs checkout at $(ERCS_ROOT)"; \
	  python3 scripts/eip-interface-drift.py \
	    --eip "$(ERCS_DRAFT)" --interfaces "$(ERCS_CONTRACTS)/interfaces" || exit 1; \
	  python3 scripts/public-input-drift.py \
	    --eip "$(ERCS_DRAFT)" --oracle "$(ERCS_CONTRACTS)/ERC8262Oracle.sol" \
	    --proof-types "$(ERCS_CONTRACTS)/libraries/ProofTypes.sol" || exit 1; \
	else \
	  echo "==> no ethereum/ERCs checkout at $(ERCS_ROOT) -- skipping submitted-copy checks"; \
	  echo "    (set ERCS_ROOT=/path/to/ERCs to include them)"; \
	fi

fixtures: check-toolchain ## Generate proof fixtures for all circuits
	./scripts/generate-fixtures.sh

snapshot: ## Capture gas snapshot (deterministic tests only; fuzz/invariant excluded)
	FOUNDRY_PROFILE=default $(FORGE) snapshot --no-match-contract InvariantTest --no-match-test "testFuzz_"

benchmark: ## Run gas benchmarks with report
	$(FORGE) test --match-contract GasBenchmark -vvv --gas-report

# ── Clean ────────────────────────────────────────────────────

clean: ## Remove build artifacts
	$(FORGE) clean
	rm -rf node_modules
	@for c in $(CIRCUITS); do \
		rm -rf circuits/$$c/target; \
	done
