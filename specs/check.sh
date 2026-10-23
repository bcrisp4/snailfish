#!/usr/bin/env bash
# Check the delivery model. Exit 0 only if every check passes.
#  1. Typecheck every file.
#  2. Run the scenario tests.
#  3. Run each config with the invariants that must hold for it.
#  4. Run each config with the invariants that must FAIL for it (known limits).
#  5. Run each mutant: at least one invariant must fail.
#  6. Run the witnesses: each must be reached in at least one trace.
# A pass is a sampled result, not a proof. SAMPLES and STEPS set the effort.
set -euo pipefail
cd "$(dirname "$0")"

SAMPLES="${SAMPLES:-20000}"
STEPS="${STEPS:-50}"
SEED="${SEED:-}"
fail=0

run() { # file module invariant -> exit status of quint run
  local seed_arg=()
  [[ -n "$SEED" ]] && seed_arg=(--seed "$SEED")
  quint run "$1" --main "$2" --invariant "$3" --max-steps "$STEPS" \
    --max-samples "$SAMPLES" --verbosity 0 "${seed_arg[@]}" >/dev/null 2>&1
}

ok() { printf '  ok    %s\n' "$*"; }
bad() { printf '  FAIL  %s\n' "$*"; fail=1; }

SAFE="noDoubleApply noLostChange noLostChangeWeak appliedHeld caughtUpState refusedNotStored noFork"
# The invariants for each mutant baseline. noFork and refusedNotStored are
# known violations with a silent rollback (limit 1, F1) or an engine state loss
# (F4), so base_fork and base_engine do not check them.
MUT_RESTORE="noDoubleApply noLostChangeWeak appliedHeld caughtUpState refusedNotStored noFork"
MUT_FORK="noDoubleApply noLostChangeWeak appliedHeld caughtUpState"
MUT_ENGINE="noDoubleApply noLostChangeWeak appliedHeld caughtUpState noFork"
invs_for() { # module -> invariant list
  case "$1" in
    m_adoptFork|base_fork) echo "$MUT_FORK" ;;
    m_resetDropsOutbox|base_engine) echo "$MUT_ENGINE" ;;
    *) echo "$MUT_RESTORE" ;;
  esac
}

echo "== typecheck"
for f in delivery.qnt delivery_test.qnt delivery_mutants.qnt; do
  if quint typecheck "$f" >/dev/null 2>&1; then ok "$f"; else bad "$f"; fi
done

echo "== tests"
if quint test delivery_test.qnt --main deliveryTest >/dev/null 2>&1; then ok "deliveryTest"; else bad "deliveryTest"; fi

echo "== invariants that must hold"
check_hold() { # module invariants...
  local m="$1"; shift
  for i in "$@"; do
    if run delivery.qnt "$m" "$i"; then ok "$m $i"; else bad "$m $i (violated)"; fi
  done
}
check_hold crashOnly    $SAFE
check_hold appRestore   $SAFE
check_hold engineLoss   noDoubleApply noLostChange noLostChangeWeak appliedHeld caughtUpState noFork
check_hold relayRestore $SAFE
check_hold faultyRelay  noDoubleApply noLostChange noLostChangeWeak appliedHeld caughtUpState
check_hold allFaults    noDoubleApply noLostChangeWeak appliedHeld caughtUpState

echo "== known limits: these must be violated"
check_limit() { # module invariant reason
  if run delivery.qnt "$1" "$2"; then bad "$1 $2 holds, expected a violation: $3"
  else ok "$1 $2 violated: $3"; fi
}
check_limit faultyRelay noFork           "silent rollback forks the log (T7 limit)"
check_limit faultyRelay refusedNotStored "refusal after a rollback, then a repair stores the change"
check_limit allFaults   noLostChange     "engine state loss plus a second fault loses a change"
check_limit engineLoss  refusedNotStored "F4: a new engine refuses a stored change over the size limit"

echo "== mutants: at least one invariant must fail"
for m in $(grep -oE '^module m_[A-Za-z]+' delivery_mutants.qnt | cut -d' ' -f2); do
  invs=$(invs_for "$m")
  caught=""
  for i in $invs; do
    if ! run delivery_mutants.qnt "$m" "$i"; then caught="$i"; break; fi
  done
  if [[ -n "$caught" ]]; then ok "$m caught by $caught"; else bad "$m survived"; fi
done
for b in base_restore base_fork base_engine; do
  for i in $(invs_for "$b"); do
    if run delivery_mutants.qnt "$b" "$i"; then ok "$b $i (baseline)"
    else bad "$b $i (violated: the mutant baseline must pass)"; fi
  done
done

echo "== witnesses (allFaults)"
W=$(grep -oE '^  val w[A-Za-z]+' delivery.qnt | awk '{print $2}')
out=$(quint run delivery.qnt --main allFaults --invariant true --max-steps 60 \
        --max-samples "$SAMPLES" --witnesses $W 2>&1 || true)
for w in $W; do
  line=$(grep -E "^$w was witnessed" <<<"$out" || true)
  n=$(sed -E 's/.* in ([0-9]+) trace.*/\1/' <<<"$line")
  if [[ -n "$line" && "$n" -gt 0 ]]; then ok "$w ($n traces)"; else bad "$w not reached"; fi
done

echo
if [[ $fail -eq 0 ]]; then echo "ALL CHECKS PASSED (sampled, $SAMPLES traces x $STEPS steps)"; else echo "CHECKS FAILED"; fi
exit $fail
