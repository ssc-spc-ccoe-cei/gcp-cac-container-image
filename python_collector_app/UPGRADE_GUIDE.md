# Upgrade Guide

This document covers how to upgrade dependencies in this project.

For current and previous versions, see `UPGRADE_CHANGELOG.md`.

## Architecture

**Dockerfiles:**
- `Dockerfile` - Python app (multi-stage build)
- `Dockerfile_custom_opa` - OPA container

Both use `ARG` variables at the top for easy version management:
- `Dockerfile`:
    - `PYTHON_VERSION`
    - `ALPINE_VERSION`
    - `CLOUD_SDK_VERSION`

- `Dockerfile_custom_opa`:
    - `CLOUD_SDK_VERSION`
    - `OPA_VERSION`

**Python packages:**
- `requirements.in`: direct dependencies (manually maintained)
- `requirements.txt`: lockfile (generated via `uv pip compile`)

## Finding Available Upgrades

### 1. Cloud SDK Container Image

**Find latest stable alpine version:**

```bash
# 1. Find the latest stable version number
gcloud container images list-tags gcr.io/google.com/cloudsdktool/cloud-sdk --filter="tags:stable" --limit=1
```

Use that version with the **-alpine** suffix.

Example: if output shows 556.0.0-stable, use 556.0.0-alpine

Or list alpine tags directly:


```bash
gcloud container images list-tags gcr.io/google.com/cloudsdktool/cloud-sdk --filter="tags:alpine" --limit=10
```

### 2. Python Container Image

**Check Python version in cloud-sdk image:**

```bash
docker run --rm gcr.io/google.com/cloudsdktool/cloud-sdk:<VERSION>-alpine python3 --version
```

Match the version of this Python with the version of your container image.

### 3. Python Packages

**See available upgrades:**

```bash
uv pip compile requirements.in --upgrade
```

**Save upgrades:**

```bash
uv pip compile requirements.in --upgrade -o requirements.txt
```

**Review changes:**

```bash
git diff requirements.txt
```

Look for:
- **Major version bumps** (e.g., 1.x → 2.x) - check changelog for breaking changes
- **New dependencies**
- **Removed packages**

**Check changelogs:**
- PyPI: `https://pypi.org/project/<package-name>/`

---

### 4. Open Policy Agent (OPA)

**Find latest version:**

```bash
curl -s https://api.github.com/repos/open-policy-agent/opa/releases/latest | jq -r '.tag_name'
```

Or visit: https://github.com/open-policy-agent/opa/releases.

View the changelog at the link above.

---

## Performing Upgrades

### Update Dockerfiles

Edit the `ARG` variables at the top of each Dockerfile:

**Dockerfile:**
```dockerfile
ARG PYTHON_VERSION=<VERSION>
ARG ALPINE_VERSION=<VERSION>
ARG CLOUD_SDK_VERSION=<VERSION>
```

**Dockerfile_custom_opa:**
```dockerfile
ARG CLOUD_SDK_VERSION=<VERSION>
ARG OPA_VERSION=<VERSION>
```

## Testing Strategy

### End-to-End Testing

1. **Run baseline job** with current versions
2. **Download results** from GCS bucket
3. **Perform upgrades**
4. **Run upgrade job** with new versions
5. **Download results** again
6. **Compare results**

### Downloading Results

**Before upgrade:**

```bash
gsutil cp gs://<BUCKET_NAME>/results-<ORG_NAME>.json ./results-before.json
```

**After upgrade:**

```bash
gsutil cp gs://<BUCKET_NAME>/results-<ORG_NAME>.json ./results-after.json
```

### Comparing Results

```bash
# Quick diff between both files
diff results-before.json results-after.json
```

If no differences: **upgrade successful.**

If differences exist: investigate what changed and why.
