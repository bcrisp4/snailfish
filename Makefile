# Verification entry points. See AGENTS.md and specs/README.md.
# Run `mise install` once. It installs every tool at its pinned version.

VERIFY := mise exec -- uv run --script specs/tools/verify.py
RULES := mise exec -- uv run --script specs/tools/rules.py
CARGO := mise exec -- cargo
# Kani installs this nightly. cargo-fuzz reuses it, so there is one nightly.
# `make rust-nightly-check` fails if a Kani upgrade changes it.
NIGHTLY_NAME := nightly-2026-08-21
NIGHTLY := +$(NIGHTLY_NAME)
FUZZ_SECONDS ?= 300

.PHONY: check verify-fast verify verify-deep verify-tools verify-drift \
        rust rust-lint rust-test rust-kani rust-fuzz rust-mutants rust-deny \
        rust-nightly-check verify-crypto

## The gate for each commit: Rust lint and tests, then the fast Quint tier.
check: rust verify-fast

## ---------------------------------------------------------------- Quint

## Typecheck, scenario tests, short sampling of one config. Under 1 minute.
verify-fast:
	$(RULES) check
	$(VERIFY) fast

## Every config, known limit, mutant and witness. About 6 minutes.
verify: verify-tools verify-crypto
	$(RULES) check
	$(VERIFY) full

## quint verify (Apalache): bounded exhaustive. About 5 minutes.
verify-deep:
	$(VERIFY) deep

## Tests of the verification runner itself.
verify-tools:
	uv run --with pytest pytest -q specs/tools/tests

## Fail if a DESIGN.md rule changed and no file in specs/ changed since main.
verify-drift:
	$(RULES) drift --base main

## ---------------------------------------------------------------- Rust

## Format check, clippy, tests, licences. For each commit.
rust: rust-lint rust-test rust-deny

rust-lint:
	mise exec -- taplo fmt --check mise.toml Cargo.toml crates/*/Cargo.toml crates/*/fuzz/Cargo.toml \
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

## Kani proofs (bounded model checking). About 10 minutes. Run before a merge.
rust-kani: rust-nightly-check
	$(CARGO) kani --workspace

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

## cargo-mutants on the protocol crate. A MISSED mutant fails the target.
## The exit code is not enough: cargo-mutants exits 3 for a timeout also when
## some mutants are missed. So the target reads mutants.out/missed.txt. A
## timeout is an infinite loop that the tests detect, so it is a pass.
rust-mutants:
	@$(CARGO) mutants -p snailfish-protocol; rc=$$?; \
	  missed=$$(wc -l < mutants.out/missed.txt 2>/dev/null | tr -d ' '); missed=$${missed:-0}; \
	  if [ $$rc -ne 0 ] && [ $$rc -ne 2 ] && [ $$rc -ne 3 ]; then \
	    echo "FAIL: cargo mutants exit $$rc"; exit $$rc; fi; \
	  if [ "$$missed" -ne 0 ]; then echo "FAIL: $$missed missed mutants"; exit 2; fi; \
	  echo "ok: no missed mutants"

## Licences, advisories and sources of every dependency.
rust-deny:
	$(CARGO) deny check

## ---------------------------------------------------------------- ProVerif

## ProVerif models of enrollment. Needs `opam install proverif`. About 30 seconds.
verify-crypto:
	eval $$(opam env 2>/dev/null); mise exec -- uv run --script specs/tools/proverif.py
