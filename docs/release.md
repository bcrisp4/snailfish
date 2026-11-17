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

# Make a GitHub release

The workflow `.github/workflows/release.yml` makes a GitHub release from a tag `v<version>`. The release notes come from the `## [<version>]` section of `CHANGELOG.md`. The tag ruleset "release tags" covers `refs/tags/v*`, so only an admin can create, move or delete the tag.

## Steps

1. In `CHANGELOG.md`, rename `## [Unreleased]` to `## [<version>] - <YYYY-MM-DD>`.
2. Add an empty `## [Unreleased]` section above it.
3. Merge the change to `main` through a pull request.
4. Make the tag on the merge commit: `git tag -s v<version> <commit>`.
5. Push the tag: `git push origin v<version>`.
6. If the run fails with "has no section", add the section to `CHANGELOG.md`. Then make the tag again.

# Publish the relay image

The workflow `.github/workflows/publish-image.yml` publishes the relay image to `ghcr.io/bcrisp4/snailfish-relay` for `linux/amd64` and `linux/arm64`. It runs for each push to `main` and each tag `v<version>` or `v<version>-rc.<n>`. A release tag also starts `release.yml` (see "Make a GitHub release"). The README lists the tags and the user verification commands.

| Trigger | Image tags |
| --- | --- |
| Push to `main` | `main`, `sha-<commit>` |
| Tag `v<version>-rc.<n>` | `<version>-rc.<n>`, `sha-<commit>` |
| Tag `v<version>` | `<version>`, `<major>.<minor>`, `latest`, `sha-<commit>`. From 1.0 also `<major>`. |

## Controls

| Control | Where | Reason |
| --- | --- | --- |
| Tag check | The `meta` job | A tag that is not a semantic version, or a tag on a commit that is not on `main`, stops the run. |
| Tag ruleset | GitHub ruleset "release tags" on `refs/tags/v*` | Only an admin can create, move or delete a release tag. |
| No build cache | `no-cache: true` in the `build` job | A cache entry from an earlier run cannot change a published image. |
| Pinned build inputs | The base images by digest, the actions by commit SHA, `cargo-auditable` by version, `--locked` | A moved tag or a new upstream release cannot change a build. Dependabot proposes updates after 7 days. |
| Smoke test | `tools/image-smoke-test.sh` in the `build` job | Each architecture must start healthy, read-only and with no capabilities before it gets a tag. |
| Vulnerability scan | Grype in the `build` job. The results go to code scanning. | A fixable High or Critical vulnerability stops the run. |
| Signature and provenance | cosign and `actions/attest-build-provenance` in the `merge` job | A user can verify that this workflow built the image from this repository. The job verifies both before it moves a tag. |
| Tag move after signing | The last step of the `merge` job | A moving tag never points to an index with no signature. |

## First publish

The first push makes a private package. Do these steps once:

1. Open the `snailfish-relay` package settings on GitHub.
2. Set the visibility to public.
3. Under "Manage Actions access", check that the `snailfish` repository has the write role.

## If an image is bad

1. Fix the cause on `main` through a pull request.
2. If the bad image is a release, make the next patch release. A release tag never moves.
