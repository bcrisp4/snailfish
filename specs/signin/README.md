# Sign-in model (ProVerif)

ProVerif checks the symbolic security of user sign-in and the native setup handoff in `DESIGN.md` "Interfaces" ([USR-1] to [USR-6]) and `PROTOCOL.md` section 12. The tool pin is ProVerif 2.05.

## Files

| File | Content |
| --- | --- |
| `lib.pvl` | Types, functions, the relay, the honest user, the app, the attacker account, the queries and the variant switch. |
| `signin.pv` | The design: `process System(vNone)`. |
| `<variant>.pv` | One deliberate flaw each. |
| `expect.toml` | The expected result of each query in each file. |

## What is modelled

1. The relay operator gives each honest user an invite token on a private channel. The relay stores a hash of the token. A copy of the relay storage is public (T1). [USR-1]
2. The user registers a passkey with the token, and signs in with a passkey assertion over a relay challenge. The relay selects the user only from the passkey. [USR-3]
3. A native app makes a PKCE verifier and asks the signed-in user to approve its challenge. The relay binds the code to the user and the challenge. [USR-4]
4. The redirect is public, because another app can claim the same URL scheme. The app reads a code that the attacker can replace.
5. The app exchanges the code and the verifier in a request that its device key signs. The relay binds the setup token to the device key and the user. [USR-5]
6. The app can leak its setup token. It creates a space with the token in a request that its device key signs. The relay checks the device and the tenant of the token. [USR-6]

## Attacker model

- Dolev-Yao on channel `c`, for an unbounded number of users, apps and sessions.
- TLS is a server-authenticated channel: a client encrypts its request and a fresh reply key to the relay key. The attacker can open such a channel too.
- The attacker holds its own user account on the same relay, with its own passkeys and devices.
- The user approves only a request that the own app starts. A phishing page that asks the user to approve the request of another app is outside the model.
- Ed25519, the passkey signature and SHA-256 are ideal.

## Queries and results for the design

| Query | Result | Meaning |
| --- | --- | --- |
| (a) `SpaceCreated(ten(u), d)` for an honest `u` needs `Approves(u, ch)` and `AppStarts(d, ch)` | true | Tenant isolation. A space in the tenant of an honest user needs a device whose sign-in that user approved. The attacker account cannot reach it. |
| (b) `AppGetsToken(d, ten(u))` needs `Approves(u, ch)` and `AppStarts(d, ch)` | true | An injected code cannot move an app into the tenant of the attacker. |
| (c) `PasskeyRegistered(u, p)` for an honest `u` needs `UserRegisters(u, p)` | true | Only the holder of the invite token registers a passkey, also with a copy of the relay storage. |
| Reachability of `TokenIssued`, `SpaceCreated` and `PasskeyRegistered` for an honest user | reachable (ProVerif prints "is false") | A full honest run exists, so the passes above are not empty. |

Result of `make verify-crypto`: all 30 query results of this directory match `expect.toml`. Each file takes about 0.1 seconds.

## Variants

| File | Flaw | Attack (one sentence) | Queries that fail |
| --- | --- | --- | --- |
| `no_pkce.pv` | The relay does not check the verifier. | The attacker reads the code from the public redirect and exchanges it with its own device key, or injects a code of its own account into the app. | (a), (b) |
| `unbound_token.pv` | The setup token does not name a device. | The attacker uses a leaked token with its own device key and creates a space in the tenant of the user. | (a) |
| `no_tenant_check.pv` | Space creation does not check the tenant of the token. | The attacker signs in to its own account, gets a token for its own device and creates a space in the tenant of another user. | (a) |
| `plain_invite.pv` | The relay stores the invite token, not its hash. | The attacker reads the token from a copy of the relay storage and registers its own passkey for the user. | (a), (c) |

## Limits

- No time. The 7 day invite expiry, the 60 second code expiry and the 10 minute token expiry are not checked.
- No one-use rule. A ProVerif table row cannot be removed, so the invite token and the code can be read more than once. Rust tests check one use (`specs/coverage.toml` `partial`).
- The redirect URI binding is not modelled. PKCE alone stops the code interception in the model.
- No browser. The Origin and anti-CSRF rules ([USR-7]) and the WebAuthn ceremony are outside the model (`specs/README.md` "Exclusions").
- A new invite that removes the old passkeys ([USR-2]) is not modelled.
- ProVerif proves the queries for an unbounded number of sessions. It can say "cannot be proved" for a true query. `expect.toml` has no such entry.

## Rust conformance (M5)

The model results do not verify the Rust code. These tests check the same cases through the public API.

| Model case | Rust and demo tests |
| --- | --- |
| Honest run: invite, passkey, handoff, space creation | `crates/relay/tests/user.rs::handoff_creates_a_space`, `demo/tests/test_users.py::test_first_device_gets_its_tenant_through_the_handoff` |
| `no_pkce.pv`: a wrong verifier | `crates/relay/tests/user.rs::token_exchange_refuses_a_wrong_verifier` |
| `unbound_token.pv`: a token of another device | `crates/relay/tests/user.rs::put_refuses_a_token_of_another_device` |
| `no_tenant_check.pv`: a token of another tenant | `crates/relay/tests/user.rs::put_refuses_a_token_of_another_tenant`, `demo/tests/test_users.py::test_second_user_cannot_reach_the_first_tenant` |
| `plain_invite.pv`: the stored invite | `crates/relay/tests/user.rs::directory_holds_no_invite_token` |

## Run

1. Run `eval $(opam env)` once in the shell.
2. Run `make verify-crypto` from the repo root. It runs this directory and `specs/enrollment`.
3. To run one file: `cd specs/signin` then `proverif -lib lib.pvl signin.pv`.
