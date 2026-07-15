# Release process

Tagging and the GitHub release are still manual. GHCR publication and categorized release notes are automated: publishing a GitHub release triggers `.github/workflows/docker-publish.yml` (build, push, Sigstore attestation) and `.github/release.yml` drives the auto-generated categorized notes.

## Versioning

Semantic Versioning (`MAJOR.MINOR.PATCH`).

- `MAJOR` — incompatible API/CLI changes.
- `MINOR` — new features, backwards-compatible.
- `PATCH` — bug fixes, no new features.

Pre-releases: `0.2.0-rc.1`, `0.2.0-rc.2`, ...

## Release checklist

### 1. Prep

- [ ] `CHANGELOG.md` has an entry for the new version.
- [ ] `pyproject.toml` `version` bumped.
- [ ] `CITATION.cff` `version` bumped.
- [ ] All CI green on `main`.
- [ ] `docs/ROADMAP.md` items that were shipped are moved out of the "planned" list.

### 2. Tag and GitHub release

```bash
git tag -a v0.1.0 -m "Argo Cloud OSINT Platform v0.1.0"
git push origin v0.1.0
```

Then on GitHub: **Releases** → **Draft a new release**:

- Tag: `v0.1.0`
- Title: `v0.1.0 — <one-liner>`
- Body: taken from `CHANGELOG.md` + the "GitHub release message" section of this doc.
- Attach: source `.tar.gz` and `.zip` (GitHub auto-generates them).

### 3. Build Python package

```bash
python -m build
# Output: dist/argo_cloud_osint-0.1.0.tar.gz + .whl
twine check dist/*
```

Test locally:

```bash
pip install dist/argo_cloud_osint-0.1.0-py3-none-any.whl
argo-osint --version
```

### 4. Docker image (automated)

Publishing the GitHub release (step 2) fires `.github/workflows/docker-publish.yml` on the `release: published` event: it builds the image, pushes `ghcr.io/<owner>/argo-cloud-osint-platform:<version>` and `:latest`, and attests Sigstore build provenance. No manual `docker push` needed. Verify after the workflow run:

```bash
gh attestation verify oci://ghcr.io/gnudrus-del/argo-cloud-osint-platform:<version> \
    --repo gnudrus-del/argo-cloud-osint-platform
```

To build and test the image locally first, without pushing:

```bash
docker build -t argo-cloud-osint-platform:<version> .
```

The same workflow can also be triggered manually (`workflow_dispatch`, with an explicit `tag` input) if you need to re-publish an image without cutting a new release.

### 5. PyPI publication (deferred)

Publishing to PyPI is planned **after** the package name is validated (currently reserved as `argo-cloud-osint`). Command when ready:

```bash
twine upload dist/*
```

Use a project-scoped PyPI token stored as a GitHub secret when the workflow is added.

### 6. Post-release

- [ ] Announce in Discussions.
- [ ] Update the demo instance if you run one.
- [ ] Bump `pyproject.toml` version to next `-dev` on `main`.
