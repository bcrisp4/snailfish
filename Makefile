# Verification entry points. See AGENTS.md and specs/README.md.
# Run `mise install` once. It installs every tool at its pinned version.

VERIFY := mise exec -- uv run --script specs/tools/verify.py
MODEL ?=
RULES := mise exec -- uv run --script specs/tools/rules.py
CARGO := mise exec -- cargo
# Kani installs this nightly. cargo-fuzz reuses it, so there is one nightly.
# `make rust-nightly-check` fails if a Kani upgrade changes it.
NIGHTLY_NAME := nightly-2026-08-21
NIGHTLY := +$(NIGHTLY_NAME)
FUZZ_SECONDS ?= 300
# Kani verifies this many harnesses in parallel. Each CBMC run can use several
# GB of memory, so the default stays well below the core count.
KANI_JOBS ?= 4
# The git ref that `make rust-mutants-diff` compares against.
BASE ?= main

.PHONY: vectors vectors-check bindings-python bindings-swift test-python test-swift \
        check verify-fast verify verify-deep verify-tools verify-workflows verify-drift \
        rust rust-lint rust-test rust-kani rust-fuzz rust-mutants rust-mutants-diff rust-deny \
        rust-nightly-check verify-crypto

## The gate for each commit: Rust lint and tests, the shared vectors in Go and
## Python, runner tests, then the fast Quint tier. `make test-swift` needs Xcode,
## so it runs on macOS only.
check: rust vectors-check test-python verify-tools verify-workflows verify-fast

## ---------------------------------------------------------------- Quint

## Typecheck, scenario tests, short sampling of one config. About 10 seconds.
## MODEL=<name> limits every Quint target to one model in specs/.
verify-fast:
	$(RULES) check
	$(VERIFY) fast $(MODEL)

## Every config, known limit, mutant and witness (sampled). Run before a merge.
## All models take about 22 minutes. One model: make verify MODEL=delivery.
verify: verify-tools $(if $(MODEL),,verify-crypto)
	$(RULES) check
	$(VERIFY) full $(MODEL)

## Apalache (bounded) and TLC (every reachable state of small configs). About 9 minutes.
verify-deep:
	$(VERIFY) deep $(MODEL)

## Tests of the verification runner itself.
verify-tools:
	uv run --with pytest pytest -q specs/tools/tests

## Check workflow syntax, expressions, and action inputs before a merge.
verify-workflows:
	mise exec -- actionlint

## Fail if a DESIGN.md rule changed and no model file in specs/ changed since BASE.
## It also fails if BASE is not a valid git commit. Default BASE is main.
verify-drift:
	$(RULES) drift --base $(BASE)

## ---------------------------------------------------------------- Rust

## Format check, clippy, tests, licences. For each commit.
rust: rust-lint rust-test rust-deny

rust-lint:
	mise exec -- taplo fmt --check mise.toml Cargo.toml crates/*/Cargo.toml crates/*/fuzz/Cargo.toml \
	  bindings/python/pyproject.toml \
	  deny.toml clippy.toml rust-toolchain.toml .cargo/mutants.toml
	$(CARGO) fmt --all --check
	$(CARGO) clippy --workspace --all-targets -- -D warnings
	@# Fuzz crates are separate workspaces, so lint each one too.
	@for dir in crates/*/fuzz; do \
	  (cd $$dir && $(CARGO) fmt --check && $(CARGO) $(NIGHTLY) clippy --all-targets -- -D warnings) || exit 1; \
	done

rust-test:
	$(CARGO) nextest run --workspace
	$(CARGO) test --workspace --doc

## Kani proofs (bounded model checking), KANI_JOBS harnesses at a time. Run before a merge.
rust-kani: rust-nightly-check
	$(CARGO) kani --workspace -j $(KANI_JOBS) --output-format terse

## Fail if the nightly that Kani installed is not NIGHTLY_NAME.
rust-nightly-check:
	@kani_version=$$($(CARGO) kani --version | awk 'NR==1 {print $$4}'); \
	  kani_nightly=$$(sed 's/-aarch64.*//; s/-x86_64.*//' $$HOME/.kani/kani-$$kani_version/rust-toolchain-version 2>/dev/null); \
	  if [ "$$kani_nightly" != "$(NIGHTLY_NAME)" ]; then \
	    echo "FAIL: Kani uses '$$kani_nightly', the Makefile uses '$(NIGHTLY_NAME)'. Update NIGHTLY_NAME."; exit 1; fi; \
	  echo "ok: nightly $(NIGHTLY_NAME) matches Kani"

## Each fuzz target for FUZZ_SECONDS (default 300). Seeds are in fuzz/seeds/.
rust-fuzz: rust-nightly-check
	@for dir in crates/*/fuzz; do \
	  for target in $$(cd $$dir && $(CARGO) $(NIGHTLY) fuzz list); do \
	    echo "== fuzz $$dir $$target ($(FUZZ_SECONDS)s)"; \
	    mkdir -p $$dir/corpus/$$target; \
	    (cd $$dir && $(CARGO) $(NIGHTLY) fuzz run $$target corpus/$$target seeds/$$target \
	      -- -max_total_time=$(FUZZ_SECONDS)) || exit 1; \
	  done; \
	done

## cargo-mutants. A MISSED mutant fails the target. The exit code alone is not
## enough: cargo-mutants exits 3 for a timeout also when some mutants are
## missed. So the check reads mutants.out/missed.txt. A timeout is an infinite
## loop that the tests detect, so it is a pass.
define check_mutants
	rc=$$?; \
	  missed=$$(wc -l < mutants.out/missed.txt 2>/dev/null | tr -d ' '); missed=$${missed:-0}; \
	  if [ $$rc -ne 0 ] && [ $$rc -ne 2 ] && [ $$rc -ne 3 ]; then \
	    echo "FAIL: cargo mutants exit $$rc"; exit $$rc; fi; \
	  if [ "$$missed" -ne 0 ]; then echo "FAIL: $$missed missed mutants"; exit 2; fi; \
	  echo "ok: no missed mutants"
endef

## Mutants of every crate in the workspace. Run nightly, and before a release.
rust-mutants:
	@$(CARGO) mutants --workspace; $(check_mutants)

## Mutants in the Rust code that changed since BASE (default main). Run before a
## merge. It does not see a test that a change made weaker in other code, so
## rust-mutants still runs nightly.
rust-mutants-diff:
	@trap 'rm -f mutants.diff' EXIT; \
	  git rev-parse --verify --quiet '$(BASE)^{commit}' > /dev/null || { echo "FAIL: BASE '$(BASE)' is not a git commit"; exit 1; }; \
	  git diff $(BASE) -- '*.rs' > mutants.diff || { echo "FAIL: git diff $(BASE) failed"; exit 1; }; \
	  if [ ! -s mutants.diff ]; then echo "ok: no Rust change since $(BASE)"; exit 0; fi; \
	  $(CARGO) mutants --workspace --in-diff mutants.diff; $(check_mutants)

## Licences, advisories and sources of every dependency.
rust-deny:
	$(CARGO) deny check

## ---------------------------------------------------------------- Vectors and bindings

GO := mise exec -- go
# The iOS simulator for `make test-swift`. Override with an ID from `xcrun simctl list devices`.
IOS_SIM ?= platform=iOS Simulator,name=iPhone 18 Pro
DEVELOPER_DIR ?= /Applications/Xcode.app/Contents/Developer

## Write vectors/*.json again with the Go generator. Only after a format change in PROTOCOL.md.
vectors:
	$(GO) run -C tools/vectorgen . -out ../../vectors

## Go checks every committed vector, and opens the key sets that Rust seals.
## The Rust tests write target/vectors/rust-sealed.json, so they run first.
vectors-check:
	cd tools/vectorgen && $(GO) vet ./... && test -z "$$(gofmt -l .)" && $(GO) test ./...
	$(GO) run -C tools/vectorgen . -check ../../vectors
	$(CARGO) nextest run -p snailfish-protocol -E 'test(key_sets_from_rust_seal_for_go)'
	$(GO) run -C tools/vectorgen . -open-rust ../../target/vectors/rust-sealed.json

bindings-python:
	bindings/scripts/build.sh python

bindings-swift:
	DEVELOPER_DIR=$(DEVELOPER_DIR) bindings/scripts/build.sh swift

## The shared vectors through the Python binding, with ruff and pyright.
test-python: bindings-python
	cd bindings/python && mise exec -- uv run --locked ruff check . && mise exec -- uv run --locked ruff format --check . \
	  && mise exec -- uv run --locked pyright && mise exec -- uv run --locked pytest

## The shared vectors through the Swift binding on an iOS simulator and on macOS.
test-swift: bindings-swift
	cd bindings/swift && DEVELOPER_DIR=$(DEVELOPER_DIR) xcodebuild test -scheme Snailfish \
	  -destination '$(IOS_SIM)' -derivedDataPath ../../target/swift-dd
	cd bindings/swift && DEVELOPER_DIR=$(DEVELOPER_DIR) xcodebuild test -scheme Snailfish \
	  -destination 'platform=macOS,arch=arm64' -derivedDataPath ../../target/swift-dd

## ---------------------------------------------------------------- ProVerif

## ProVerif models of enrollment. Needs `opam install proverif`. About 30 seconds.
verify-crypto:
	eval $$(opam env 2>/dev/null); mise exec -- uv run --script specs/tools/proverif.py
