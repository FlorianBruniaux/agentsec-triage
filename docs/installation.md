# Installing AgentSec Triage

AgentSec Triage is currently reviewed and run from its public source checkout.
No PyPI package, tag, source archive, or GitHub release is authorized.

## Requirements

Use a Python version supported by [`pyproject.toml`](../pyproject.toml). The
current compatibility matrix and release-specific values live in the
[changelog](../CHANGELOG.md).

Git is needed to obtain the source checkout. AgentSec does not invoke Git while
scanning an untrusted repository.

## Install from the source checkout

Create an isolated environment and install the project with its development
dependencies:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
```

The installation step may resolve dependencies. Repository scans run offline by
default and do not fetch threat intelligence.

If every required package is already cached, an offline uv installation is also
supported:

```bash
uv venv
uv pip install --offline -e ".[dev]"
```

To expose `agentsec` globally while keeping it in an isolated environment, use
an editable install from the local checkout:

```bash
uv tool install --editable --offline /absolute/path/to/agentsec-triage
agentsec doctor
```

The checkout must remain at that path. Source changes become visible to the
global command without publishing or reinstalling the package.

## Verify the installation

Run both supported entry points:

```bash
.venv/bin/agentsec doctor
.venv/bin/python -m agentsec doctor
```

A valid source environment reports the Python runtime, bundled database,
resource availability, `scan-result-v2: valid`, and
`batch-result-v1: valid`. Then inspect the command surface:

```bash
.venv/bin/agentsec --help
.venv/bin/agentsec batch --help
.venv/bin/agentsec detectors list
.venv/bin/agentsec db info
```

## Windows PowerShell

```powershell
py -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\agentsec doctor
.venv\Scripts\python -m agentsec doctor
```

Use `.venv\Scripts\agentsec` in place of `.venv/bin/agentsec` for the
examples in this repository.

## Distribution status

Do not install AgentSec from an unofficial package index or source archive.
The source repository is public, but [`LICENSE-DECISION.md`](../LICENSE-DECISION.md)
still blocks tags, archives, and package publication until the separate data
review is complete.
