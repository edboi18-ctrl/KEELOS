# Repository setup checklist (P0-T9)

These are GitHub settings only the repository owner can change. The agent
does not change repository settings (spec section 1, rule 9). Tick each
item in `docs/STATUS.md` once done. Menu names are GitHub's as of
November 2026 and may move; the setting names are what matter.

Repository: `edboi18-ctrl/KEELOS`

## 1. Visibility and license

- [ ] **Settings → General → Danger Zone → Change visibility: Public.**
      Hosted runners are free and artifact attestations are available for
      public repositories (decision D13).
- [x] License files are on `main`: `LICENSE-MIT`, `LICENSE-APACHE`.

## 2. Protect `main` (SR-36)

**Settings → Rules → Rulesets → New branch ruleset**, target the default
branch (`main`), enforcement **Active**:

- [ ] Restrict deletions.
- [ ] Block force pushes.
- [ ] Require a pull request before merging.
      Also tick **Require review from Code Owners** so that changes under
      `.github/` need your approval (`.github/CODEOWNERS`).
- [ ] Require status checks to pass, and add both CI jobs:
      `Audit and host tests` and `Build and boot tests (QEMU with KVM)`.
      They appear in the picker after CI has run once.
- [ ] Do not add yourself to a bypass list unless you need it; a bypass
      turns the rule into a suggestion.

## 3. Actions permissions (SR-32, SR-33)

**Settings → Actions → General**:

- [ ] Actions permissions: **Allow edboi18-ctrl, and select non-edboi18-ctrl,
      actions and reusable workflows**, with **Allow actions created by
      GitHub** ticked and nothing else. All four actions in use are
      GitHub's own (`docs/DEPENDENCIES.md`).
- [ ] Tick **Require actions to be pinned to a full-length commit SHA**.
- [ ] Workflow permissions: **Read repository contents and packages
      permissions** (read-only default token).
- [ ] Leave **Allow GitHub Actions to create and approve pull requests**
      unticked.
- [ ] Approval for running fork pull request workflows: **Require approval
      for all external contributors**.
- [ ] Runners: do not add self-hosted runners to this repository.

## 4. Tags and releases (SR-35)

**Settings → Rules → Rulesets → New tag ruleset**, target `v*`:

- [ ] Restrict creations, updates, and deletions to yourself, so only you
      can cause a release.

A release is made by tagging a commit that is already on `main`:

```powershell
git tag v0.1.0 <commit-on-main>
git push origin v0.1.0
```

The `release` workflow refuses a tag whose commit is not on `main`.

## 5. Secrets (SR-34)

- [ ] **Settings → Secrets and variables → Actions**: keep this empty.
      The build needs no secrets, and `cargo xtask audit` rejects any
      workflow that references one.

## 6. Verifying a release on your PC

Install the GitHub CLI (`winget install GitHub.cli`), then download the
release files into one folder and, from a checkout of this repository:

```powershell
cargo xtask verify C:\path\to\keel-0.1.0.img
cargo xtask verify C:\path\to\keel-0.1.0-esp.zip
```

Each command checks the file against `SHA256SUMS` and asks GitHub for a
build-provenance attestation signed by this repository's `release.yml`.
Use a file only if the command ends with `is verified.`

## 7. Nothing personal in the repository (SR-37)

Before every push, check that no file, log, or screenshot contains the
machine's service tag, serial numbers, MAC addresses, or a home-directory
path. Kernel builds remap host paths (`xtask/src/build.rs`).
