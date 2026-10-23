# Verification entry points. See AGENTS.md and specs/README.md.
# Run `mise install` once to get quint, java and python.

VERIFY := mise exec -- uv run --script specs/tools/verify.py
RULES := mise exec -- uv run --script specs/tools/rules.py

.PHONY: verify-fast verify verify-deep verify-tools verify-drift

## Typecheck, scenario tests, short sampling of one config. Under 1 minute.
verify-fast:
	$(RULES) check
	$(VERIFY) fast

## Every config, known limit, mutant and witness. About 6 minutes.
verify: verify-tools
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
