"""In-house perforce package."""

import importlib

from . import perforce as _perforce_impl
from .perforce import *  # noqa: F401,F403


def reload_runtime():
    """
    Reload the implementation module so cached connection state is rebuilt.
    Returns the reloaded implementation module.
    """
    global _perforce_impl
    _perforce_impl = importlib.reload(_perforce_impl)
    exported_names = getattr(_perforce_impl, "__all__", None)
    if exported_names is None:
        exported_names = [name for name in dir(_perforce_impl) if not name.startswith("_")]
    for name in exported_names:
        globals()[name] = getattr(_perforce_impl, name)
    globals()["_perforce_impl"] = _perforce_impl
    return _perforce_impl
