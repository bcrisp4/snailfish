# Verification entry points. See AGENTS.md and specs/README.md.
# Run `mise install` once to get quint, java and python.

VERIFY := mise exec -- uv run --script specs/tools/verify.py

.PHONY: verify-fast verify verify-deep verify-tools

## Typecheck, scenario tests, short sampling of one config. Under 1 minute.
verify-fast:
	$(VERIFY) fast

## Every config, known limit, mutant and witness. About 6 minutes.
verify: verify-tools
	$(VERIFY) full

## quint verify (Apalache): bounded exhaustive. About 5 minutes.
verify-deep:
	$(VERIFY) deep

## Tests of the verification runner itself.
verify-tools:
	uv run --with pytest pytest -q specs/tools/tests
