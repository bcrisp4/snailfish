# Enrollment model (ProVerif)

ProVerif checks the symbolic security of Enrollment in `DESIGN.md` (steps 1 to 9). The tool pin is ProVerif 2.05 via `opam install proverif`.

## Files

| File | Content |
| --- | --- |
| `lib.pvl` | Types, crypto functions, processes `T`, `N` and `User`, the queries and the variant switch. |
| `enrollment.pv` | The design: `process System(vNone)`. |
| `<variant>.pv` | One deliberate flaw each. Each file is one line: `process System(vX)`. |
| `expect.toml` | The expected result of each query in each file. |

## What is modelled

1. The trusted device `T` opens a session and shows its session ID. The new device `N` reads the ID from the attacker. [ENR-1]
2. `N` sends its public keys (one signing key, one KEM key) and its metadata. `T` sends its public keys. [ENR-3]
3. `T` sends a commitment to its nonce and to both key sets. `N` sends its nonce. `T` reveals its nonce. `N` checks the commitment. [ENR-4] [ENR-5] [ENR-6]
4. Each device derives the code: a truncated hash of both key sets and both nonces. Each device shows it on its own screen. [ENR-7]
5. The `User` process presses confirm on both devices only if the two codes are equal. [ENR-7]
6. `N` sends a confirmation that it signs over the session ID, both key sets, the metadata and both nonces. `T` checks it. [ENR-7]
7. `T` appends a grant (signed, with the app key sealed to the keys of `N`) and a signed checkpoint over the new log root. `N` checks both signatures and the seal. [ENR-8]

## Attacker model

- Dolev-Yao. The network and the relay are the attacker. It reads, drops, changes and makes any message on channel `c`, for an unbounded number of sessions.
- The attacker can make its own device keys and nonces. It knows the public key of `T`.
- The screens and the confirm buttons are private channels. The attacker cannot read or press them. The user pairs any `T` screen with any `N` screen.
- The attacker has two extra functions, `ngrind` and `tgrind`. They give it the last nonce that makes the truncated code equal to a chosen code. This is the 1-in-10^6 search, repeated about 10^6 times. A design must stop the attacker from choosing the last nonce after it knows the other nonce.
- X-Wing is an ideal KEM. Ed25519 is an ideal signature. The commitment is a hash with no inverse.

## One input, one value

ProVerif turns each input of a process into a rule that any message can trigger. It does not count uses. Without a limit, one `T` session could take two different nonces from `N`, reveal its nonce for the first and show the code for the second. A real session reads each input once.

`lib.pvl` has one event for each input and one `restriction` for each event. A restriction says that one session reads one value for that input. A confirm press also names the code that the user compared. Without the code, `T` would take a confirm that the user gave to a different pairing. Without these two limits, ProVerif reported "cannot be proved" for every security query and printed an attack that no real run can make.

## Queries and results for the design

| Query | Result | Meaning |
| --- | --- | --- |
| `inj-event(TAppends) ==> inj-event(NConfirms)` | true | Each grant that `T` appends has one new device that confirmed the same session, keys and metadata. |
| `inj-event(NAccepts) ==> inj-event(TAppends)` | true | Each grant that `N` accepts comes from one `T` session with the same session ID and metadata. |
| `event(NAccepts) ==> event(TSignsCp)` | true | `N` accepts a log root only if `T` signed a checkpoint for it. |
| `not attacker(appk)` | true | The attacker never learns the app key. |
| `not event(TAppends)`, `NConfirms`, `NAccepts`, `UserConfirms` | reachable (ProVerif prints "is false") | A full honest run exists. The passes above are not empty. |

Result of `make verify-crypto`: all 56 query results match `expect.toml`. The run takes about 30 seconds. The files run in parallel. `user_blind.pv` takes about 40 seconds and each other file under 7 seconds.

## Variants

Each variant breaks at least one query that the design passes.

| File | Flaw | Attack (one sentence) | Queries that fail |
| --- | --- | --- | --- |
| `no_commit.pv` | `T` sends its nonce in clear instead of a commitment. | The attacker reads the nonce of `T` before it sends its own nonce. It then picks a nonce that makes the truncated code equal on both screens, although it substitutes its own keys. | injective agreement, `NAccepts`, `TSignsCp`, `appk` |
| `no_key_binding.pv` | The commitment and the code do not cover the keys. | The attacker forwards the nonces unchanged and swaps the keys, so both screens show the same code. | injective agreement, `NAccepts`, `TSignsCp`, `appk` |
| `user_blind.pv` | The user confirms without comparing the codes. | The attacker runs one session with each device and substitutes its own keys. The codes differ, the user confirms anyway, and `T` appends the attacker keys. | injective agreement, `NAccepts`, `TSignsCp`, `appk` |
| `conf_unsigned.pv` | The confirmation of `N` has no signature. | The attacker sends `T` any bytes as the confirmation, so `T` appends a grant for a session in which `N` never confirmed. | agreement, `NAccepts` |
| `conf_no_meta.pv` | The signed confirmation leaves out the metadata. | The attacker changes the device name before `T` reads it. The signature of `N` does not cover the name, so `T` appends the changed name. | agreement (`TAppends` to `NConfirms`) |
| `cp_unsigned.pv` | The checkpoint has no signature. | The attacker makes a checkpoint for a log root that `T` never signed, and `N` accepts it. | `NAccepts ==> TSignsCp` |

Variants that broke nothing and were dropped: a commitment without the keys (the code still has them), and a code without the keys (the commitment still has them). Either binding alone is enough in the model. Both must go to break it, which is `no_key_binding.pv`.

## Findings

No finding E1: no query is false for the design as written in `DESIGN.md`.

- E0 (model note). The first draft reported "cannot be proved" for every query. The cause was the model, not the design. See "One input, one value". The queries did not change.
- E2 (design note). `DESIGN.md` says "a signed confirmation" and points to `PROTOCOL.md` for the transcript. `PROTOCOL.md` does not exist in this branch. The model signs the label, the session ID, both key sets, the metadata and both nonces. `conf_unsigned.pv` and `conf_no_meta.pv` show that the session ID and the metadata must be in the signed data. `PROTOCOL.md` must list them.

## Limits

- No probability. The claim "a relay that substitutes keys gets one guess at the code for each session" is NOT checked. The model only shows that the attacker cannot choose the last nonce after it knows the other nonce. It does not count guesses.
- No timing. The 10 minute expiry and the "each session works once" rule are not checked. The model limits each session to one value for each input.
- X-Wing is an ideal KEM and Ed25519 is an ideal signature. Hybrid or combiner flaws are out of scope.
- Step 9 is partial. `N` checks the grant, the checkpoint signature and the seal. It does not check the log from the genesis record. [ENR-9]
- No tenants, no routes, no protocol level. [ENR-2]
- The "reachable" results show that one honest run exists. They do not show that every interleaving works.
- ProVerif proves the queries for an unbounded number of sessions. It can say "cannot be proved" for a true query. `expect.toml` has no such entry for the design.

## Run

1. Run `eval $(opam env)` once in the shell. It puts ProVerif on `PATH`.
2. Run `make verify-crypto` from the repo root.
3. To run one file: `cd specs/enrollment` then `proverif -lib lib.pvl enrollment.pv`.
4. To read an attack: add `-html /tmp/out` to the command and open `/tmp/out/index.html`.

`make verify` runs `verify-crypto`. `make verify-fast` does not.

## Change the model

1. Change `lib.pvl` or add a `<variant>.pv` file.
2. Add the file and each query result to `expect.toml`.
3. Cite each `DESIGN.md` rule in a `(* Rules: [ENR-n] *)` comment.
4. Run `make verify-crypto` and `mise exec -- uv run --script specs/tools/rules.py check`.
