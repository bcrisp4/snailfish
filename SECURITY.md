# Security policy

## Report a vulnerability

Do not open a public issue for a security problem. Report it through [GitHub private vulnerability reporting](https://github.com/bcrisp4/snailfish/security/advisories/new).

Include the version or commit, the steps to reproduce, and the impact.

## Supported versions

Only the latest release of the `snailfish` Python package and the latest commit of `main` get security fixes.

## Scope

These problems are in scope:

- A relay that reads app data, or a relay operator who can make a device accept a record that its user did not write.
- A path to the data of another tenant on a shared relay.
- A sign-in, invite or setup token flaw that gives a session or a device to the wrong user.
- A parser fault in the engine or the relay that untrusted bytes can reach.
- A log line or a metric that holds app data, a key, a token or a user name.

The security model is in [DESIGN.md](DESIGN.md). The formal models and their attacker assumptions are in [specs/](specs/README.md).
