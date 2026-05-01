# perforce

Shared Perforce wrapper package for Python tools (forked from `dm_perforce` for JAM/Spark use).

This package centralizes the Perforce helper logic that was previously vendored inside individual apps.

## Scope
Current module:
- `perforce.perforce`

Current public API comes from `src/perforce/perforce.py` (re-exported by `perforce.__init__`).

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
import perforce as p4

con = p4.connect(force=True, search_path="//depot/project/...")
local_path = p4.P4File.get_local_file("//depot/project/file.txt")
p4.P4File.get_latest("//depot/project/file.txt")
```

Check if a file exists in Perforce:

```python
import perforce as p4

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
- Tools should `import perforce` directly.
