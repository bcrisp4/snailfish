# Release the Python package

This runbook publishes the `snailfish` wheels to PyPI. The workflow `.github/workflows/release-python.yml` builds, tests and publishes them.

## What a release holds

A release is three binary wheels, one for each platform: macOS arm64, Linux x86_64 and Linux aarch64 (manylinux 2_28). Each wheel holds the engine library of `crates/bindings`, its UniFFI module, the two licence files and an SBOM of the Rust dependencies. A release has no source distribution.

## Controls

| Control | Where | Reason |
| --- | --- | --- |
| PyPI trusted publishing | PyPI project `snailfish`: repository `bcrisp4/snailfish`, workflow `release-python.yml`, environment `pypi` | The workflow gets a short-lived token through OIDC. No PyPI token exists to leak. |
| Required reviewer | GitHub environment `pypi`: reviewer `bcrisp4` | A tag push alone cannot publish. A person approves each upload. |
| Tag policy | GitHub environment `pypi`: deployment ref `py-v*`, type tag | A run from a branch or another tag cannot use the environment. |
| Tag ruleset | GitHub ruleset "release tags" on `refs/tags/py-v*` | Only an admin can create, move or delete a release tag. |
| Pinned build inputs | Actions pinned by commit SHA, `maturin==1.15.0`, the Rust toolchain of `rust-toolchain.toml`, the uv version of `mise.toml` | A moved tag or a new upstream release cannot change a release build. Dependabot proposes updates after 7 days. |
| Version check | The first step of the `build` job | A tag that differs from `version` in `bindings/python/pyproject.toml` stops the run. |
| Wheel test | The `test` job | Each wheel installs in a clean venv on its platform and runs the shared vectors before the upload. |

## Steps

1. Set `version` in `bindings/python/pyproject.toml`. PyPI refuses a version that it holds already, also after a deletion.
2. Merge the change to `main` through a pull request.
3. Make the tag on the merge commit: `git tag -s py-v<version> <commit>`.
4. Push the tag: `git push origin py-v<version>`.
5. Open the run in the Actions tab. Wait for the `build` and `test` jobs.
6. If a `build` or `test` job fails, read its log and fix the cause. Delete the tag and make it again on the fixed commit.
7. Approve the `publish` job in the run.
8. Install the release in a clean venv: `uv run --isolated --with snailfish==<version> python -c 'import snailfish'`.

## If a release is bad

PyPI does not let you replace a file. Yank the version on pypi.org, so that a new install does not pick it. Then release the fix with the next version number.
