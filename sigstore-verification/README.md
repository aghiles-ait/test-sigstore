# sigstore-verification

Verify the **signed SLSA provenance** of a container image to prove, from a deployed
image, exactly which **source code** it was built from (repository + commit).

Two equivalent implementations:

| Script | Verification dependency | Use case |
|---|---|---|
| [`verify-provenance.sh`](verify-provenance.sh) | [`cosign`](https://github.com/sigstore/cosign) binary | CLI, CI |
| [`verify-js/verify-provenance.js`](verify-js/verify-provenance.js) | [`sigstore-js`](https://github.com/sigstore/sigstore-js) library (pure JS) | UI backend, environment without `cosign` |

Both produce identical output.

## What it verifies

Starting from a **trusted image digest** (typically provided by a remote TDX attestation
certifying the image actually deployed), the script:

1. **fetches** the attestation bundle from the GitHub API, **by digest**;
2. **verifies the signature**: Fulcio certificate chain + inclusion in the Rekor
   transparency log + expected OIDC issuer (GitHub Actions);
3. **verifies the signer identity**: the certificate SAN must match the signing workflow's
   repository (`^https://github.com/<sign-action-repo>/`);
4. **verifies the binding**: the attestation `subject` must be **exactly** the supplied
   digest — guarantees the attestation refers to *this* image;
5. **prints** the source: repository, commit, and triggering workflow.

> **No registry access is required.** Since the digest comes from a trusted source and is
> content-addressed, the whole verification is done from the bundle (fetched via GitHub) —
> never by querying the image registry.

## Prerequisites

**Shell script:**
- `cosign` (`brew install cosign`)
- `jq`, `curl`

**JS script:**
- Node.js ≥ 18 (for global `fetch`)
- dependencies installed:
  ```bash
  cd verify-js && npm install
  ```

## Usage

```bash
# Shell
./verify-provenance.sh <entrypoint-workflow-repo> <sign-action-repo> <sha256-digest>

# JS
node verify-js/verify-provenance.js <entrypoint-workflow-repo> <sign-action-repo> <sha256-digest>
```

- `<entrypoint-workflow-repo>`: GitHub repository whose event triggered the run — the one
  that **owns the attestation** (queried via the GitHub API), in `owner/name` format.
- `<sign-action-repo>`: GitHub repository of the workflow that **signs** the attestation
  (the reusable workflow), in `owner/name` format. Constrains the certificate identity.
  Pass the **same value** as the first argument when signing is not done from a reusable
  workflow.
- `<sha256-digest>`: image digest. Both `sha256:abc…` and `abc…` forms are accepted.

> **Why two repos?** With keyless signing, the certificate identity (SAN) points to the
> workflow that actually ran the signing step. If that step lives in a reusable workflow
> hosted in a *different* repository, the signer identity differs from the repository that
> owns the attestation — hence the two distinct arguments. When everything is in one repo,
> pass it twice.

### Example

```bash
# Signing in the same repo (typical case): pass the repo twice
./verify-provenance.sh \
  aghiles-ait/test-sigstore \
  aghiles-ait/test-sigstore \
  0a50000fc886c537e42d1a953449be0d37af9a2f6fb296a55cdf11403110969a

# Signing via a reusable workflow hosted in another repo
./verify-provenance.sh \
  aghiles-ait/test-sigstore \
  aghiles-ait/ci-workflows \
  0a50000fc886c537e42d1a953449be0d37af9a2f6fb296a55cdf11403110969a
```

Output:

```
✅ Attestation SLSA vérifiée et liée à l'image déployée
   image    : sha256:0a50000fc886c537e42d1a953449be0d37af9a2f6fb296a55cdf11403110969a
   source   : git+https://github.com/aghiles-ait/test-sigstore@refs/tags/v0.2.0
   commit   : 4035c60570386a8c797164ffbdaf0d688fb04fe2
   workflow : https://github.com/aghiles-ait/test-sigstore/.github/workflows/docker-build-on-tag.yaml@refs/tags/v0.2.0
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Attestation valid, signed by the expected repository, bound to the supplied image |
| `1` | Failure: attestation missing, invalid signature/identity, or digest mismatch |
| `2` | Misuse (missing or invalid arguments) |

Usable as-is as a **gate** in a pipeline (e.g. right after receiving the digest from a
TDX attestation).

## Environment variable

| Variable | Effect |
|---|---|
| `GITHUB_TOKEN` | Authenticates the GitHub API call — required for a **private** repository, or to avoid the anonymous API rate limit. |

```bash
GITHUB_TOKEN=ghp_xxx ./verify-provenance.sh <entrypoint-workflow-repo> <sign-action-repo> <sha256-digest>
```

## Notes

- **Division of responsibility (JS).** `sigstore-js` only offers *exact* identity
  matching, while the signer identity embeds the workflow git ref (`…@refs/tags/vX`),
  which varies from one release to another. The script therefore delegates the
  cryptographic verification + issuer check to the library, and applies the **regexp** on
  the SAN itself — the equivalent of `cosign`'s `--certificate-identity-regexp`.
- The `--new-bundle-format has been deprecated` warning (shell) is harmless: it will be
  the only supported format going forward.
- The first run of the JS script downloads the Sigstore trusted root via TUF (from the
  public Sigstore infrastructure, **not** the registry) and caches it.
