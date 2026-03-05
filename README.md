# dm_perforce

Shared Perforce wrapper package for Python tools.

This package centralizes the Perforce helper logic that was previously vendored inside individual apps.

## Scope
Current module:
- `dm_perforce.perforce`

Current public API comes from `src/dm_perforce/perforce.py` (re-exported by `dm_perforce.__init__`).

## Requirements
- Python 3.11+
- `p4python` (installed via package dependency on Windows)
- Perforce CLI/session configured on the machine (workspace/client, login, network/VPN)

## Install
Local editable/development install:

```powershell
python -m pip install -e .
```

Regular install:

```powershell
python -m pip install .
```

## Key APIs
Connection and environment:
- `connect(client=None, force=False, search_path=None)`
- `auto_configure_connection(...)`
- `set_connection_environment(data)`
- `clear_connection_environment()`
- `reset_connection_caches()`

Core helpers:
- `P4File.exists_in_p4(path, include_add=False)`
- `P4File.get_local_file(depot_path)`
- `P4File.get_latest(path, force=False, safe=False)`
- `p4_sync(path, client=None)`
- `p4_check_out(path, connection)`
- `p4_add(path, connection)`
- `p4_check_in(path, connection, comment="")`

Additional classes:
- `P4EditFileContext`
- `P4ChangeList`
- `Workspace`

## Usage examples
Resolve a depot path to local and sync latest:

```python
import dm_perforce as p4

con = p4.connect(force=True, search_path="//depot/project/...")
local_path = p4.P4File.get_local_file("//depot/project/file.txt")
p4.P4File.get_latest("//depot/project/file.txt")
```

Check if a file exists in Perforce:

```python
import dm_perforce as p4

state, info = p4.P4File.exists_in_p4("//depot/project/file.txt", include_add=True)
```

## Packaging and release
Build wheel:

```powershell
python -m pip install build
python -m build
```

Artifacts are created in `dist/` and can be published from CI/GitHub release.

## Notes
- This is currently an extracted wrapper and may be refactored into a smaller stable API.
- Existing tools can migrate from `import perforce` to `import dm_perforce as perforce`.

## GitHub Actions (wheel build)
The repo includes `.github/workflows/build-wheel.yml`:
- On push/PR: builds `sdist` + `wheel` and uploads `dist/*` as artifacts.
- On `v*` tag push: creates a GitHub release and attaches built files.

## UV install from release
After tagging (for example `v0.1.0`), UV can install the release wheel directly:

```powershell
uv pip install "https://github.com/<owner>/dm_perforce/releases/download/v0.1.0/dm_perforce-0.1.0-py3-none-any.whl"
```
