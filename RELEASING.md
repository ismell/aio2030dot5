# Releasing

Releases are built and published by `.github/workflows/release.yml` with PyPI
trusted publishing: no API token exists anywhere.

## One-time setup

- **PyPI and TestPyPI**: a *pending* trusted publisher (Account → Publishing; the
  project does not exist there until its first upload) for project `aio2030dot5`,
  owner `ismell`, repository `aio2030dot5`, workflow `release.yml`, environments
  `pypi` and `testpypi` respectively.
- **GitHub environments** (Settings → Environments):
  - `pypi`: deployment branches and tags limited to tags matching `v*`, and a
    required reviewer.
  - `testpypi`: deployment branches limited to `main`.
- **Tag protection** (Settings → Rules): a ruleset for tags `v*` that only the
  maintainer may create.
- **Private vulnerability reporting** (Settings → Code security): on, as
  `SECURITY.md` promises.

## A release

1. Update `CHANGELOG.md` (with the date) and `__version__` in
   `src/aio2030dot5/__init__.py`; merge to `main` with CI green.
2. Optional dry run: run the Release workflow by hand on `main`. It publishes
   `<version>.devN` to TestPyPI; check the page and `pip install` it from there.
3. Tag and push: `git tag -a v<version> -m v<version> && git push origin v<version>`
   (`-s` instead of `-a` signs the tag, if you have a signing key on GitHub).
   The workflow runs the full CI, checks that the tag matches `__version__`,
   builds, and waits for the `pypi` environment's approval before publishing.
4. Create the GitHub release from the tag, with the CHANGELOG entry as notes.

If the PyPI upload fails halfway (one file uploaded), do not re-run the job: PyPI
refuses a file that already exists. Download the `dist` artifact from the run and
upload the missing file with `twine upload` and an API token scoped to this project
(delete the token right afterwards), or
release the next patch version.
