# Release process

Manual for now. Automated release-notes and GHCR publication are tracked as a roadmap item (see `.github/workflows/release.yml` scaffolding when it lands).

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

### 4. Docker image

```bash
docker build -t argo-cloud-osint-platform:0.1.0 .
```

Optional GHCR push (manual for now):

```bash
echo $GITHUB_TOKEN | docker login ghcr.io -u <your-user> --password-stdin
docker tag argo-cloud-osint-platform:0.1.0 ghcr.io/<your-user>/argo-cloud-osint-platform:0.1.0
docker tag argo-cloud-osint-platform:0.1.0 ghcr.io/<your-user>/argo-cloud-osint-platform:latest
docker push ghcr.io/<your-user>/argo-cloud-osint-platform:0.1.0
docker push ghcr.io/<your-user>/argo-cloud-osint-platform:latest
```

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
