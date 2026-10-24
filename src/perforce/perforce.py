__author__ = "david moulder"

import logging
import os
import re
import socket
import stat
import sys
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional

import P4
from P4 import P4Exception

try:
    import P4API
except ImportError:
    P4API = None

if "pipeline_launcher" in sys.modules:
    log = logging.getLogger("pipeline_launcher.perforce")
else:
    log = logging.getLogger("perforce")
log.setLevel(logging.INFO)

DEFAULT_COMMENT = "Perforce Check In"
G_CON = None
# P4Python connections are native objects and are not safe to enter from two
# threads at once. Maya legitimately asks Perforce from both its UI thread and
# background workers (for example, an icon fallback while selected-details is
# inventorying an asset). Keep the existing shared connection semantics, but
# serialize its complete command and lifecycle boundary.
#
# Re-entrant rather than a plain Lock because command recovery calls back into
# reset/connect while the failed command still owns the gate.
P4_RUNTIME_LOCK = threading.RLock()
P4_DISCOVERY_TRACE_ENV_VAR = "JAM_P4_DISCOVERY_TRACE"
TRUTHY_ENV_VALUES = {"1", "true", "yes", "on"}
USER_WORKSPACE_CACHE = {}
AUTH_ERROR_FRAGMENTS = (
    "your session has expired",
    "perforce password (p4passwd) invalid or unset",
    "password invalid or unset",
)


@dataclass(frozen=True)
class P4MoveMapping:
    """One native Perforce source/destination move pair."""

    source: str
    destination: str


@dataclass(frozen=True)
class P4PendingMovePair:
    """One reciprocal native move pair found in a pending changelist."""

    source: str
    destination: str
    changelist: str


@dataclass(frozen=True)
class P4MoveFileReport:
    """Read-only eligibility report for one proposed move."""

    source: str
    destination: str
    source_depot: str = ""
    destination_depot: str = ""
    have_revision: int = 0
    head_revision: int = 0
    source_action: str = ""
    source_change: str = ""
    destination_action: str = ""
    destination_change: str = ""
    is_staged: bool = False
    other_open: tuple = ()
    other_lock: tuple = ()
    issues: tuple = ()

    @property
    def is_ready(self):
        return not self.is_staged and not self.issues


@dataclass(frozen=True)
class P4MovePreview:
    """Complete non-mutating report for a proposed native move batch."""

    files: tuple
    depot_only: bool = False

    @property
    def is_ready(self):
        return bool(self.files) and all(report.is_ready for report in self.files)

    @property
    def has_staged_files(self):
        return any(report.is_staged for report in self.files)

    @property
    def is_fully_staged(self):
        return bool(self.files) and all(report.is_staged for report in self.files)

    @property
    def can_resume(self):
        """Return whether a partial native move can safely finish in place."""

        return (
            self.has_staged_files
            and not self.is_fully_staged
            and all(report.is_staged or report.is_ready for report in self.files)
        )

    @property
    def issues(self):
        return tuple(issue for report in self.files for issue in report.issues)


@dataclass(frozen=True)
class P4MoveExecution:
    """Truthful staged/unstarted result from a stop-on-first-failure batch."""

    staged: tuple = ()
    unstarted: tuple = ()
    failed: P4MoveMapping | None = None
    error: str = ""

    @property
    def succeeded(self):
        return self.failed is None and not self.unstarted and not self.error


@dataclass(frozen=True)
class P4MoveVerification:
    """Verification of native move/add and move/delete pairs."""

    mapping: P4MoveMapping
    source_action: str = ""
    destination_action: str = ""
    is_valid: bool = False
    issues: tuple = ()


def _p4_error_message(error):
    if isinstance(error, BaseException):
        lines = list(getattr(error, "errors", []) or [])
        if lines:
            return "\n".join(str(line) for line in lines)
    return str(error)


class PerforceAuthenticationError(RuntimeError):
    """Perforce refused the command because nobody is logged in.

    A `RuntimeError` subclass so existing `except RuntimeError` handlers keep
    catching it, and its own type so callers that can say something useful are
    able to tell it apart from every other Perforce failure.

    It exists because the distinction was being established and then discarded.
    `patched_run` tests `_is_auth_error`, so at that moment the cause is known
    exactly; it then raised a bare "Perforce connection recovery failed", and
    `Library.root_local_path` relabelled that as "check PIPELINE_DEPOT_ROOT_RAW
    and the active client mapping". An artist whose ticket had expired was told
    to check an environment variable they have never heard of.
    """

    #: What to tell somebody who is not a pipeline engineer.
    ADVICE = "Your Perforce session has expired. Log in to Perforce and try again."


def _is_auth_error(error):
    message = _p4_error_message(error).lower()
    return any(fragment in message for fragment in AUTH_ERROR_FRAGMENTS)


def _is_truthy_env_var(name):
    value = os.environ.get(name, "")
    return value.strip().lower() in TRUTHY_ENV_VALUES


def _display_env_value(value):
    if value is None:
        return "<unset>"

    text = str(value).strip()
    return text or "<unset>"


def _connection_summary(connection):
    if connection is None:
        return "<none>"

    try:
        return "port={port} user={user} client={client} connected={connected}".format(
            port=_display_env_value(getattr(connection, "port", None)),
            user=_display_env_value(getattr(connection, "user", None)),
            client=_display_env_value(getattr(connection, "client", None)),
            connected=getattr(connection, "connected", lambda: False)(),
        )
    except Exception:
        return repr(connection)


def discovery_trace_enabled():
    return log.isEnabledFor(logging.DEBUG) or _is_truthy_env_var(
        P4_DISCOVERY_TRACE_ENV_VAR
    )


def discovery_trace(message, *args, exc_info=False):
    if not discovery_trace_enabled():
        return

    level = logging.DEBUG if log.isEnabledFor(logging.DEBUG) else logging.INFO
    log.log(level, "[discovery] " + message, *args, exc_info=exc_info)


_ORIGINAL_P4_RUN = P4.P4.run


def patched_run(self, *args, **kargs):
    """Run one native Perforce command without sharing P4API concurrently."""
    with P4_RUNTIME_LOCK:
        return _run_with_reauthentication(self, *args, **kargs)


def _run_with_reauthentication(self, *args, **kargs):
    """Patched run implementation with session re-authentication."""
    if P4API is None:
        return _ORIGINAL_P4_RUN(self, *args, **kargs)

    context = {}
    resultLogging = True

    if "resultLogging" in kargs:
        resultLogging = False
        del kargs["resultLogging"]

    for k, v in list(kargs.items()):
        context[k] = getattr(self, k)
        setattr(self, k, v)

    __flatten_method = getattr(self, f"_{self.__class__.__name__}__flatten", None)
    if not __flatten_method:
        raise AttributeError(
            f"Cannot access __flatten method in class {self.__class__.__name__}"
        )

    flatArgs = __flatten_method(args)

    if self.logger:
        self.logger.info("p4 " + " ".join(flatArgs))

    if hasattr(self, "encoding") and self.encoding and not self.encoding == "raw":
        result = []
        for s in flatArgs:
            if isinstance(s, str):
                result.append(s.encode(self.encoding))
            else:
                result.append(s)
        flatArgs = result

    try:
        result = P4API.P4Adapter.run(self, *flatArgs)
    except P4.P4Exception as e:
        if _is_auth_error(e):
            if self.logger:
                self.logger.warning(
                    "Perforce auth failure detected. Resetting cached connection state and retrying."
                )
            try:
                reset_runtime_state(connection=self)
                self.port = os.environ.get("P4PORT", self.port)
                self.user = os.environ.get("P4USER", self.user)
                self.client = os.environ.get("P4CLIENT", self.client)
                self.connect()
                if os.environ.get("P4PASSWD"):
                    self.relogin()
                result = P4API.P4Adapter.run(self, *flatArgs)
            except Exception as login_error:
                for k, v in list(context.items()):
                    setattr(self, k, v)
                if self.logger:
                    self.logger.error(
                        f"Perforce connection recovery failed: {login_error}"
                    )
                # Named, because we already know what went wrong. Recovery only
                # relogins when P4PASSWD is set, and nobody stores a Perforce
                # password, so an expired ticket reaches here every time -- and
                # "recovery failed" is the one thing nobody can act on.
                raise PerforceAuthenticationError(
                    PerforceAuthenticationError.ADVICE
                ) from login_error
        else:
            for k, v in list(context.items()):
                setattr(self, k, v)
            raise e

    if self.logger:
        self.log_messages()

    if resultLogging and self.logger:
        self.logger.debug(result)

    for k, v in list(context.items()):
        setattr(self, k, v)

    return result


def relogin(self):
    """
    Re-authenticate to Perforce when the session expires.
    Assumes 'P4PASSWD' is set in the environment or managed securely.
    """
    if self.logger:
        self.logger.info("Attempting to login to Perforce...")

    with P4_RUNTIME_LOCK:
        try:
            password = os.environ.get("P4PASSWD", "")
            if not password:
                raise RuntimeError("P4PASSWD is not set.")
            _ORIGINAL_P4_RUN(self, "login", password.encode("utf-8"))
            if self.logger:
                self.logger.info("Re-login successful.")
        except Exception as e:
            if self.logger:
                self.logger.exception("Failed to login to Perforce.")
            raise RuntimeError("Perforce login failed.") from e


if P4API is not None:
    P4.P4.run = patched_run
    P4.P4.relogin = relogin


def is_login_required(connection):
    info = connection_info(connection)
    return info["logged_in"]


def new_connection(level=1):
    """
    Ensure the same connection is established with the right levels
    Args:
        level: int 1 # Only fail on errors, not warnings

    Returns: P4.P4()

    """
    p4 = P4.P4()
    p4.exception_level = level
    return p4


def _apply_connection_environment(connection):
    if connection is None:
        return None

    env_values = {
        "port": os.environ.get("P4PORT"),
        "user": os.environ.get("P4USER"),
        "client": os.environ.get("P4CLIENT"),
    }

    if connection.connected():
        mismatched_values = []
        for attr, env_value in env_values.items():
            if env_value and str(getattr(connection, attr, "")) != str(env_value):
                mismatched_values.append(f"{attr}={env_value}")
        if mismatched_values:
            discovery_trace(
                "Skipping environment update on connected Perforce connection (%s): %s",
                _connection_summary(connection),
                ", ".join(mismatched_values),
            )
        return connection

    for attr, env_value in env_values.items():
        if env_value:
            setattr(connection, attr, env_value)
    return connection


def connection_info(con):
    if not con:
        con = connect()
    info = dict(
        user=con.user,
        host=con.host,
        port=con.port,
        client=con.client,
        cwd=con.cwd,
        connected=con.connected(),
        tickets=[],
        logged_in=False,
    )
    info["tickets"] = con.run_tickets()
    if all([info["connected"], info["tickets"]]):
        info["logged_in"] = True
    return info


def _is_local_path_within(path, root):
    """Return whether a local path is contained by a workspace root."""

    if not path or not root:
        return False
    normalized_path = os.path.normcase(os.path.abspath(os.path.normpath(path)))
    normalized_root = os.path.normcase(os.path.abspath(os.path.normpath(root)))
    try:
        return os.path.commonpath((normalized_path, normalized_root)) == normalized_root
    except ValueError:
        return False


def _get_path_matching_workspaces(workspaces, search_path):
    if not search_path or search_path.startswith("//"):
        return []

    matches = []
    for workspace in workspaces:
        workspace_root = workspace.get("Root", "")
        if _is_local_path_within(search_path, workspace_root):
            matches.append((len(workspace_root), workspace))

    matches.sort(key=lambda item: item[0], reverse=True)
    return [workspace for _, workspace in matches]


def _fallback_workspace_connection_for_path(path=None):
    preferred_port = os.environ.get("P4PORT")
    preferred_user = os.environ.get("P4USER")
    preferred_client = os.environ.get("P4CLIENT")
    discovery_trace(
        "Attempting host-workspace fallback for %s with preferred port=%s user=%s client=%s",
        _display_env_value(path),
        _display_env_value(preferred_port),
        _display_env_value(preferred_user),
        _display_env_value(preferred_client),
    )

    if not preferred_port:
        discovery_trace("Host-workspace fallback skipped because P4PORT is unset")
        return {}

    p4 = new_connection()
    p4.port = preferred_port
    if preferred_user:
        p4.user = preferred_user
    if preferred_client:
        p4.client = preferred_client

    try:
        p4.connect()
        info = p4.run("info") or []
        resolved_user = preferred_user
        if info:
            resolved_user = info[0].get("userName") or resolved_user
        if resolved_user:
            p4.user = resolved_user

        workspaces = Workspace.get_user_workspaces(p4_con=p4)
        if not workspaces:
            discovery_trace("Host-workspace fallback found no host-matched workspaces")
            return {}

        path_matches = _get_path_matching_workspaces(workspaces, path)
        selected_workspace = None
        if path_matches:
            selected_workspace = path_matches[0]
            discovery_trace(
                "Host-workspace fallback matched search path to client=%s root=%s",
                selected_workspace.get("client") or selected_workspace.get("Client"),
                selected_workspace.get("Root", ""),
            )
        elif len(workspaces) == 1:
            selected_workspace = workspaces[0]
            discovery_trace(
                "Host-workspace fallback selected sole workspace client=%s root=%s",
                selected_workspace.get("client") or selected_workspace.get("Client"),
                selected_workspace.get("Root", ""),
            )
        else:
            discovery_trace(
                "Host-workspace fallback found %d candidate workspaces but could not resolve a unique match",
                len(workspaces),
            )
            return {}

        return {
            "PORT": str(preferred_port),
            "P4USER": str(resolved_user or selected_workspace.get("Owner", "") or ""),
            "Workspace": str(
                selected_workspace.get("client")
                or selected_workspace.get("Client")
                or ""
            ),
        }
    except Exception as error:
        discovery_trace(
            "Host-workspace fallback failed for %s: %s", path, error, exc_info=True
        )
        return {}
    finally:
        try:
            if p4.connected():
                p4.disconnect()
        except Exception:
            pass


def _filter_connections_by_preferred_port(connections, preferred_port):
    if not preferred_port:
        return connections

    matching_connections = [c for c in connections if c.get("PORT") == preferred_port]
    if matching_connections:
        return matching_connections

    log.warning(
        "Ignoring %d recent Perforce connection(s) because none matched requested P4PORT %s",
        len(connections),
        preferred_port,
    )
    discovery_trace(
        "No recent connection candidates matched requested P4PORT=%s",
        preferred_port,
    )
    return []


def _auto_configure_connection_for_path(path=None):
    if not path:
        path = get_this_path()

    preferred_port = os.environ.get("P4PORT")
    valid_connections = _filter_connections_by_preferred_port(
        get_valid_p4_connections(),
        preferred_port,
    )
    if not valid_connections:
        fallback_connection = _fallback_workspace_connection_for_path(path)
        if fallback_connection:
            log.info(
                "Auto-configured connection for %s using host workspace fallback: %s",
                path,
                fallback_connection["Workspace"],
            )
            set_connection_environment(fallback_connection)
            return fallback_connection
        log.warning(
            "No valid Perforce connections available. Check your network/VPN status."
        )
        return {}

    for connection in valid_connections:
        try:
            p4 = P4.P4()
            p4.port = connection.get("PORT")
            p4.user = connection.get("P4USER")
            p4.client = connection.get("Workspace")

            p4.connect()
            try:
                where_result = p4.run("where", path)
                if where_result:
                    p4.disconnect()
                    log.info(
                        f"Auto-configured connection for {path}: {connection['PORT']}"
                    )
                    set_connection_environment(connection)
                    return connection
            except P4Exception:
                pass
            p4.disconnect()
        except Exception as e:
            log.debug(
                f"Error testing connection {connection.get('PORT')} for path {path}: {str(e)}"
            )
            continue

    fallback_connection = _fallback_workspace_connection_for_path(path)
    if fallback_connection:
        log.info(
            "Auto-configured connection for %s using host workspace fallback: %s",
            path,
            fallback_connection["Workspace"],
        )
        set_connection_environment(fallback_connection)
        return fallback_connection

    if preferred_port:
        log.warning(
            "No recent Perforce connection mapped %s on requested server %s",
            path,
            preferred_port,
        )
        return {}

    log.info(f"Using first valid connection: {valid_connections[0]['PORT']}")
    set_connection_environment(valid_connections[0])
    return valid_connections[0]


def auto_configure_connection(*args, **kwargs):
    client = None
    connection = None
    search_path = None
    path = None

    if args:
        if len(args) == 1 and isinstance(args[0], str):
            path = args[0]
        else:
            if len(args) > 0:
                client = args[0]
            if len(args) > 1:
                connection = args[1]
            if len(args) > 2:
                search_path = args[2]

    if "client" in kwargs:
        client = kwargs["client"]
    if "connection" in kwargs:
        connection = kwargs["connection"]
    if "search_path" in kwargs:
        search_path = kwargs["search_path"]
    if "path" in kwargs:
        path = kwargs["path"]

    if connection is None and client is None and search_path is None:
        return _auto_configure_connection_for_path(path)

    if connection is None and client is None and search_path is not None:
        return _auto_configure_connection_for_path(search_path)

    discovery_trace(
        "Auto-configuring connection with requested client=%s current_connection=%s search_path=%s",
        _display_env_value(client),
        _connection_summary(connection),
        _display_env_value(search_path),
    )

    if search_path:
        data = find_matching_workspace(search_path)
        if data[0] is None:
            connection_data = _auto_configure_connection_for_path(search_path)
            if connection_data:
                connection.port = connection_data.get("PORT", connection.port)
                connection.user = connection_data.get("P4USER", connection.user)
                connection.client = connection_data.get("Workspace", connection.client)
                return True
            raise Exception("No workspace found")

        p4con = connect_to_perforce(data)
        if p4con:
            connection.port = str(p4con.port)
            connection.user = p4con.user
            connection.client = p4con.client
            if p4con is not connection:
                try:
                    if p4con.connected():
                        p4con.disconnect()
                except Exception:
                    pass
            return True
        return False

    if client is None:
        if connection:
            connection.client = os.environ.get("P4CLIENT", connection.client)
            connection.user = os.environ.get("P4USER", connection.user)
            connection.port = os.environ.get("P4PORT", connection.port)
            connection.connect()
            return True
        return False
    return True

    # # for key, value in connection_data.items():
    # #     log.debug("Perforce Connection Data  >  {} : {}".format(key, value))
    # #     if value:
    # #         # if getattr(connection, key, "") != value:
    # #         try:
    # #             setattr(connection, key, value)
    # #             log.debug(
    # #                 "Changing Perforce Connection Attr  >  {} : {}".format(key, value)
    # #             )
    # #         except P4.P4Exception as e:
    # #             pass
    #
    # if client is None:
    #     if not connection_data["client"]:
    #         client = client_from_here(connection, search_path)
    #         log.info("Connection is acquiring client")
    #         if client != "no matching client found":
    #             log.info("SETTING CLIENT : {}".format(client))
    #             os.environ["P4CLIENT"] = client
    #             connection_data["client"] = client
    #             connection.client = client
    #             return True
    #         else:
    #             log.warning(
    #                 "Could not configure perforce connection : {}".format(
    #                     connection_info(connection)
    #                 )
    #             )
    #             return False
    #     return True
    # return True


def clear_connection_environment():
    keys = ["P4CONFIG", "P4PORT", "P4CLIENT", "P4USER"]
    discovery_trace("Clearing connection environment keys: %s", ", ".join(keys))
    for key in keys:
        os.environ.pop(key, None)


def set_connection_environment(data: dict):
    assert isinstance(data, dict)
    for key, value in data.items():
        log.info(f"Setting OS Environment Var : {key} : {value}")
        os.environ[key.upper()] = value
        if key.upper() == "PORT":
            log.info(f"Setting OS Environment Var : P4PORT : {value}")
            os.environ["P4PORT"] = value
        if key == "Workspace":
            log.info(f"Setting OS Environment Var : P4CLIENT : {value}")
            os.environ["P4CLIENT"] = value


def reset_connection_caches():
    """
    Clear lru_cache-backed Perforce discovery caches.
    Useful when network/VPN state changes while the launcher is running.
    """
    cached_funcs = [
        get_valid_p4_connections,
        _auto_configure_connection_for_path,
    ]
    for fn in cached_funcs:
        clear = getattr(fn, "cache_clear", None)
        if callable(clear):
            clear()
    USER_WORKSPACE_CACHE.clear()


def reset_runtime_state(connection=None):
    """
    Clear cached connection discovery and drop the shared connection object.
    This is the programmatic equivalent of reloading the module after VPN/auth changes.
    """
    with P4_RUNTIME_LOCK:
        return _reset_runtime_state(connection)


def _reset_runtime_state(connection=None):
    """Reset cached native state while the caller owns ``P4_RUNTIME_LOCK``."""
    global G_CON

    targets = [connection]
    if G_CON is not connection:
        targets.append(G_CON)

    for target in targets:
        if not target:
            continue
        try:
            if target.connected():
                target.disconnect()
        except Exception:
            pass

    G_CON = None
    reset_connection_caches()


@lru_cache
def get_p4_recent_connections():
    import os
    import xml.etree.ElementTree as ET

    # Form the path to the bookmarks file
    file_path = os.path.join(
        os.getenv("USERPROFILE"), ".p4qt", "ApplicationSettings.xml"
    )

    if not os.path.exists(file_path):
        log.warning(f"{file_path} not found to retrieve recent connections")
        discovery_trace("Recent connections file missing: %s", file_path)
        return []

    # Parse the XML file
    tree = ET.parse(file_path)
    root = tree.getroot()
    data = []

    # Navigate to RecentConnections
    for elem in root.iter("PropertyList"):
        if "varName" in elem.attrib and elem.attrib["varName"] == "Connection":
            for sub_elem in elem.iter("StringList"):
                if (
                    "varName" in sub_elem.attrib
                    and sub_elem.attrib["varName"] == "RecentConnections"
                ):
                    for string_elem in sub_elem.iter("String"):
                        raw_value = string_elem.text or ""
                        parts = raw_value.replace(" ", "").split(",")
                        parts = [p for p in parts if p]
                        if len(parts) == 3:
                            if all(parts):
                                data.append(
                                    {
                                        "PORT": parts[0],
                                        "P4USER": parts[1],
                                        "Workspace": parts[2],
                                    }
                                )
                            else:
                                log.warning(
                                    "Ignoring malformed recent Perforce connection entry: %s",
                                    raw_value,
                                )
                        else:
                            log.warning(
                                "Ignoring malformed recent Perforce connection entry: %s",
                                raw_value,
                            )
                            discovery_trace(
                                "Skipping malformed recent connection entry: %s",
                                raw_value,
                            )
    log.debug(f"Recent Connections: {data}")
    discovery_trace("Parsed %d recent connection(s) from %s", len(data), file_path)
    return data


@lru_cache(maxsize=128)
def get_valid_p4_connections():
    """
    Try to connect to all recent P4 connections and return only the ones that work.
    This helps avoid the issue of failing on VPN-dependent connections when VPN is not active.

    Returns:
        list: A list of dictionaries containing valid connection configurations.
    """
    valid_connections = []
    recent_connections = get_p4_recent_connections()

    for connection in recent_connections:
        p4 = P4.P4()
        p4.port = connection.get("PORT")
        p4.user = connection.get("P4USER")
        p4.client = connection.get("Workspace")

        try:
            p4.connect()
            p4.run("info")
            valid_connections.append(connection)
            log.debug(f"Valid connection found: {connection['PORT']}")
            p4.disconnect()
        except Exception as e:
            log.debug(f"Connection failed for {connection.get('PORT')}: {str(e)}")
            continue

    if not valid_connections:
        log.warning("No valid P4 connections found. Check your network/VPN status.")

    return valid_connections


def find_matching_workspace(search_path):
    log.info(f"finding workspace : {search_path}")

    if search_path is None:
        return None, None

    preferred_port = os.environ.get("P4PORT")
    preferred_user = os.environ.get("P4USER")
    preferred_client = os.environ.get("P4CLIENT")
    recent_connections = _filter_connections_by_preferred_port(
        get_p4_recent_connections(),
        preferred_port,
    )
    discovery_trace(
        "Finding workspace for %s with preferred port=%s user=%s client=%s",
        search_path,
        _display_env_value(preferred_port),
        _display_env_value(preferred_user),
        _display_env_value(preferred_client),
    )

    def prefer_connection(connections, key, value):
        if value:
            filtered = [c for c in connections if c.get(key) == value]
            if filtered:
                return filtered
        return connections

    recent_connections = prefer_connection(recent_connections, "P4USER", preferred_user)
    recent_connections = prefer_connection(
        recent_connections, "Workspace", preferred_client
    )
    discovery_trace(
        "Testing %d recent connection candidate(s)", len(recent_connections)
    )

    # needs to be standard paths

    matching_workspace = None
    port = ""
    p4 = None
    # Initialize a new P4 connection
    for connection in recent_connections:
        p4 = new_connection()
        p4.port = connection["PORT"]
        p4.user = connection["P4USER"]
        p4.client = connection["Workspace"]
        workspace_name = connection["Workspace"]
        discovery_trace(
            "Testing connection port=%s user=%s client=%s",
            connection["PORT"],
            connection["P4USER"],
            workspace_name,
        )

        try:
            p4.connect()
            workspace = None
            try:
                workspace = p4.fetch_client(workspace_name)
            except P4.P4Exception as e:
                log.warning(e)
                discovery_trace("fetch_client failed for %s: %s", workspace_name, e)

            if search_path.startswith("//"):
                depot_candidates = [search_path]
                if "..." not in search_path:
                    depot_candidates.append(search_path.rstrip("/") + "/...")

                matching_candidate = None
                for candidate in depot_candidates:
                    try:
                        files = p4.run("files", candidate)
                    except Exception as e:
                        log.error(e)
                        discovery_trace(
                            "files lookup failed for %s in client=%s: %s",
                            candidate,
                            workspace_name,
                            e,
                        )
                        files = []
                    if files:
                        matching_candidate = candidate
                        discovery_trace(
                            "files lookup matched %s in client=%s",
                            candidate,
                            workspace_name,
                        )
                        break
                    discovery_trace(
                        "files lookup returned no results for %s in client=%s",
                        candidate,
                        workspace_name,
                    )

                if matching_candidate:
                    if workspace:
                        try:
                            p4.client = workspace_name
                            where_info = p4.run("where", matching_candidate)
                        except P4.P4Exception as e:
                            log.error(e)
                            discovery_trace(
                                "where failed for %s in client=%s: %s",
                                matching_candidate,
                                workspace_name,
                                e,
                            )
                            where_info = []
                        if _where_has_mapping(where_info):
                            matching_workspace = workspace
                            port = connection["PORT"]
                            discovery_trace(
                                "Matched workspace via fetch_client result: client=%s root=%s",
                                workspace.get("Client") or workspace.get("client"),
                                workspace.get("Root", ""),
                            )
                            break
                        discovery_trace(
                            "where returned no mapping for %s in client=%s",
                            matching_candidate,
                            workspace_name,
                        )

                    for ws in Workspace.get_user_workspaces(p4_con=p4):
                        try:
                            p4.client = ws["client"]
                            where_info = p4.run("where", matching_candidate)
                        except P4.P4Exception as e:
                            log.debug(e)
                            discovery_trace(
                                "where failed for candidate client=%s: %s",
                                ws.get("client"),
                                e,
                            )
                            continue
                        if _where_has_mapping(where_info):
                            matching_workspace = ws
                            port = connection["PORT"]
                            discovery_trace(
                                "Matched workspace via user workspaces: client=%s root=%s",
                                ws.get("client"),
                                ws.get("Root", ""),
                            )
                            break
                        discovery_trace(
                            "where returned no mapping for candidate client=%s",
                            ws.get("client"),
                        )
                    if matching_workspace:
                        break
                continue

            if workspace:
                workspace_root = workspace.get("Root", "")
                if _is_local_path_within(search_path, workspace_root):
                    matching_workspace = workspace
                    port = connection["PORT"]
                    discovery_trace(
                        "Matched workspace by root containment: client=%s root=%s",
                        workspace.get("Client") or workspace.get("client"),
                        workspace.get("Root", ""),
                    )
                    break
                discovery_trace(
                    "Workspace root did not match search path: client=%s root=%s search=%s",
                    workspace_name,
                    workspace.get("Root", ""),
                    search_path,
                )

            for ws in Workspace.get_user_workspaces(p4_con=p4):
                workspace_root = ws.get("Root", "")
                if _is_local_path_within(search_path, workspace_root):
                    matching_workspace = ws
                    port = connection["PORT"]
                    discovery_trace(
                        "Matched workspace from user workspace list: client=%s root=%s",
                        ws.get("client"),
                        ws.get("Root", ""),
                    )
                    break
                discovery_trace(
                    "Candidate workspace root did not match search path: client=%s root=%s search=%s",
                    ws.get("client"),
                    ws.get("Root", ""),
                    search_path,
                )
            if matching_workspace:
                break

        except P4.P4Exception as e:
            log.exception(e)
            discovery_trace(
                "Connection attempt failed for client=%s: %s",
                workspace_name,
                e,
                exc_info=True,
            )

        finally:
            try:
                if p4.connected():
                    p4.disconnect()
            except Exception:
                pass

    if matching_workspace:
        discovery_trace(
            "Workspace discovery succeeded: client=%s port=%s",
            matching_workspace.get("Client") or matching_workspace.get("client"),
            port,
        )
    else:
        discovery_trace("Workspace discovery failed for %s", search_path)
    return matching_workspace, port


def _where_has_mapping(mappings):
    """Return whether ``p4 where`` contains a real, non-excluded mapping."""

    for mapping in mappings or []:
        if not isinstance(mapping, dict) or mapping.get("unmap"):
            continue
        mapped_path = mapping.get("path") or mapping.get("clientFile") or ""
        if mapped_path and not str(mapped_path).startswith("-"):
            return True
    return False


def _connection_maps_path(connection, search_path):
    """Return whether a connection's current client maps the requested path."""

    if not search_path:
        return True
    try:
        if not connection.connected():
            connection.connect()
        mappings = connection.run("where", search_path) or []
    except Exception as error:
        discovery_trace(
            "Cached connection cannot map %s: %s",
            search_path,
            error,
            exc_info=True,
        )
        return False

    return _where_has_mapping(mappings)


def _connection_matches_request(connection, client=None, search_path=None):
    """Return whether a cached connection satisfies an explicit request."""

    if connection is None:
        return False
    if (
        client
        and str(getattr(connection, "client", "")).casefold() != str(client).casefold()
    ):
        return False
    return _connection_maps_path(connection, search_path)


def connect(client=None, force=False, search_path=None):
    """
    returns a P4 connection
    :return:
    """
    with P4_RUNTIME_LOCK:
        return _connect(client=client, force=force, search_path=search_path)


def _connect(client=None, force=False, search_path=None):
    """Return the shared connection while the caller owns ``P4_RUNTIME_LOCK``."""
    global G_CON
    if force:
        reset_runtime_state()

    if (
        G_CON
        and force is False
        and not _connection_matches_request(
            G_CON,
            client=client,
            search_path=search_path,
        )
    ):
        discovery_trace(
            "Discarding cached Perforce connection for requested client=%s path=%s: %s",
            _display_env_value(client),
            _display_env_value(search_path),
            _connection_summary(G_CON),
        )
        try:
            if G_CON.connected():
                G_CON.disconnect()
        except Exception:
            pass
        G_CON = None

    if all([G_CON, force is False]):
        if not G_CON.connected():
            _apply_connection_environment(G_CON)
            try:
                G_CON.connect()
            except P4.P4Exception as error:
                if _is_auth_error(error):
                    log.warning(
                        "Cached Perforce connection failed auth. Recreating connection."
                    )
                    return connect(client=client, force=True, search_path=search_path)
                raise
        return G_CON

    G_CON = new_connection()

    effective_search_path = search_path or get_this_path()
    success = auto_configure_connection(client, G_CON, effective_search_path)
    if not success:
        # Retry once after cache clear in case VPN/network became available.
        reset_connection_caches()
        success = auto_configure_connection(client, G_CON, effective_search_path)

    if not success and search_path is None:
        try:
            client_from_here(connection=G_CON, search_path=effective_search_path)
            success = True
        except Exception as error:
            discovery_trace(
                "Legacy client_from_here fallback failed for %s: %s",
                effective_search_path,
                error,
                exc_info=True,
            )

    if not success:
        raise ConnectionError(
            f"Could not connect to perforce : {connection_info(G_CON)}"
        )
    try:
        if G_CON is None:
            G_CON = new_connection()
        if not client and not search_path:
            _apply_connection_environment(G_CON)
        if not G_CON.connected():
            G_CON.connect()
    except Exception as e:
        log.exception(e)
    return G_CON


def is_frozen():
    """
    Return True if running from the frozen (i.e. compiled form) of your app, or
    False when running from source.
    """
    return getattr(sys, "frozen", False)


@lru_cache(maxsize=128)
def get_this_path():
    if is_frozen():
        return os.path.dirname(sys.executable)
    else:
        p = os.path.realpath(__file__).replace(".pyc", ".py")
        return p


def client_from_here(connection, search_path=None):
    """
    Defined the workspace as the current tools location
    """
    if any([search_path is None, search_path == ""]):
        search_path = get_this_path()

    workspace = Workspace.find(search_path, p4_con=connection)["workspace_client"]
    discovery_trace("client_from_here search_path=%s", search_path)
    discovery_trace("client_from_here workspace=%s", workspace)
    return workspace


@lru_cache
def workspace_root_from_here() -> str:
    """
    This will return the root of the P4 worksapce based on this files location and not use P4 to determine this path
    Returns: str

    """
    root_path = get_this_path()
    return os.path.normpath(f"{os.path.dirname(root_path)}\\..\\..\\..\\..\\..\\..\\")


def make_file_writable(file_path):
    if os.path.exists(file_path):
        os.chmod(file_path, stat.S_IWRITE)


class P4EditFileContext:
    def __init__(self, path, auto_add=False, auto_update=True, changelist=None):
        self.auto_add = auto_add
        self.auto_update = auto_update
        self.changelist = changelist
        self.path = path
        self.checked_out = False

    def do_checkout(self):
        P4File.check_out(
            self.path,
            changelist=self.changelist,
            auto_add=self.auto_add,
            auto_update=self.auto_update,
        )

    def __enter__(self):
        if os.path.exists(self.path):
            self.do_checkout()
            self.checked_out = True

    def __exit__(self, type, value, traceback):
        if not self.checked_out:
            self.do_checkout()


class P4File:
    @classmethod
    def info(cls, file_name, auto_add=False, changelist_number=None, record=None):
        """Read one file's Perforce state.

        ``record`` is an already-read state dict from an earlier call. The
        predicates below each used to read their own, so asking a file four
        questions cost four server round trips for one unchanging answer.
        Passing the record asks once and answers all four from it.
        """

        if record is not None:
            return record
        return Workspace.find(
            file_name=file_name, auto_add=auto_add, changelist_number=changelist_number
        )

    @classmethod
    def exists_in_p4(cls, file_name, include_add=False, record=None):
        """
        Check if a file exists in Perforce.

        Args:
            file_name (str): Path to the file to check
            include_add (bool): Whether to consider files marked for 'add' as existing
            record (dict): an already-read state dict, to avoid a second read

        Returns:
            tuple: (exists_in_p4, info_dict)
        """
        info = record if record is not None else Workspace.find(file_name, auto_add=False)

        if (
            info.get("workspace_client") == "no matching client found"
            or info.get("workspace_root") == "no matching workspace found"
        ):
            return False, info

        if not info.get("depotFile") and int(info.get("headRev", 0) or 0) <= 0:
            return False, info

        mask = ["add", "delete", "delete/move"]
        if include_add:
            mask.pop(0)
        if info.get("headAction") in ["delete", "delete/move", "move/delete"]:
            return False, info
        if info["action"] not in mask:
            return True, info
        return False, info

    @classmethod
    def get_history(cls, file_name):
        """
        Gets the history of the file in perforce
        Args:
            file_name: str

        Returns:

        """
        log.debug(f"get_history - file name : {file_name}")
        file_name = process_path(file_name)
        # A fresh P4 connection inherits whichever client P4CONFIG or the host
        # environment happens to expose from the process working directory.
        # That client may belong to another project and cannot address this
        # local path.  Route history through the same path-aware shared
        # connection used by the rest of the wrapper.
        c = connect(search_path=file_name)
        data = c.run("filelog", "-h", "-L", file_name)
        to_return = []
        import datetime

        if data:
            data = data[0]
            for row, cl in enumerate(data["change"]):
                to_return.append(
                    dict(
                        change=cl,
                        rev=data["rev"][row],
                        time=datetime.datetime.utcfromtimestamp(int(data["time"][row])),
                        user=data["user"][row],
                        description=data["desc"][row],
                        action=data["action"][row],
                    )
                )
        return to_return

    @classmethod
    def delete(cls, file_name, changelist_name=None):
        """
        Nice wrapper over marking a file for delete and also removing files not in P4 from the disk
        Args:
            file_name: str
            changelist_name: str
        Returns: None
        """
        state, info = cls.exists_in_p4(file_name)
        cl = {}
        if changelist_name:
            cl = P4ChangeList.create_changelist(
                changelist_name, info["workspace_client"]
            )
        if state:
            if info["haveRev"] != info["headRev"]:
                # TODO: Do we need to have latest to mark something for delete?
                pass

            cmd_args = ["delete"]
            if isinstance(cl, dict):
                change_idx = int(cl["Change"])
                cmd_args.extend(["-c", str(change_idx)])

            cmd_args.extend([file_name])
            con = connect()
            con.run(*cmd_args)
        else:
            if os.path.exists(file_name):
                os.remove(file_name)

    @classmethod
    def is_locked_by_other(cls, file_name, record=None):
        return bool(cls.info(file_name, record=record)["otherLock"])

    @classmethod
    def last_submission_info(cls, file_name, connection=None):
        connection = connection if not None else connect()
        submission_info = {}
        info = connection.run(
            "changes", ["-l", "-m", "1", "-s", "submitted", file_name]
        )

        for i in info:
            if "status" in i:
                submission_info["status"] = i["status"]
            if "changeType" in i:
                submission_info["changeType"] = i["changeType"]
            if "client" in i:
                submission_info["client"] = i["client"]
            if "user" in i:
                submission_info["user"] = i["user"]
            if "time" in i:
                submission_info["time"] = i["time"]
            if "path" in i:
                submission_info["path"] = i["path"]
            if "change" in i:
                submission_info["change"] = i["change"]
            if "desc" in i:
                submission_info["desc"] = i["desc"]

        return submission_info

    @classmethod
    def get_local_file(cls, depot_file):
        ws = Workspace.find(depot_file)
        found = ws.get("clientFile", "")
        if found:
            log.debug(
                f"Found from workspace clientFile {depot_file} -> {found}"
            )
            return found
        else:
            if isinstance(depot_file, str) and depot_file.startswith("//"):
                try:
                    connect(force=True, search_path=depot_file)
                except Exception as e:
                    log.debug(f"Auto-configure failed for {depot_file}: {e}")
            else:
                connect(force=True)
            found = cls._get_local_file(depot_file)
            log.debug(f"Get local file using WHERE {depot_file} -> {found}")
            return found

    @classmethod
    def _get_local_file(cls, depot_file):
        c = connect()
        p = depot_file.lstrip().rstrip()
        if not p:
            return ""

        # try and match the client to the depot path
        # workspaces = Workspace.get_user_workspaces()
        # workspace_clients = [r.get('Stream', "").lower() for r in workspaces]
        # workspaces_roots = Workspace.all_workspace_root_paths()
        # local_path = None
        #
        # # for i, r in enumerate(workspace_clients):
        # #     if r:
        # #         if depot_file.startswith(r):
        # #             local_path = process_path(p.replace(workspace_clients[i], workspaces_roots[i]))
        # #             break
        #
        # if local_path:
        #     return local_path

        if p.endswith("/"):
            p = p[:-1]

        candidates = [p]
        if p.startswith("//") and "..." not in p:
            candidates.append(p + "/...")

        def run_where(p4con, path):
            try:
                data = p4con.run("where", path)
            except Exception as e:
                log.exception(e)
                return None
            if data:
                local_path = data[-1].get("path") or data[-1].get("clientFile")
                if local_path:
                    if local_path.endswith("..."):
                        local_path = local_path[:-3]
                    return local_path.rstrip("\\/")
            return None

        for candidate in candidates:
            local_path = run_where(c, candidate)
            if local_path:
                return local_path

        if p.startswith("//"):
            try:
                connect(force=True, search_path=p)
                c = connect()
            except Exception as e:
                log.debug(f"Auto-configure failed for {p}: {e}")
            for candidate in candidates:
                local_path = run_where(c, candidate)
                if local_path:
                    return local_path

    @classmethod
    def client_file(cls, file_path):
        """
        from a depot path get the client file path
        :param file_path: //depot
        :return: local path str
        """
        return Workspace.find(file_path)

    @classmethod
    def depot_file(cls, file_path):
        log.debug(f"depot_file - file name : {file_path}")
        c = new_connection()
        c.connect()
        file_info = Workspace.find(file_path, auto_add=False)
        if not file_info:
            return
        for info in file_info:
            if "depotFile" in info:
                return file_info["depotFile"]
        return

    @classmethod
    def add(cls, file_name, changelist=None):
        log.info(f"add - file name : {file_name}")

        # initialize variables
        # file_info = Report.init_file_report_dict()
        # file_info = Report.get(file_name, file_info, p4con, False)

        file_info = Workspace.find(
            file_name, auto_add=True, changelist_number=changelist
        )
        if file_info:
            if file_info["action"] == "add":
                return file_info
            else:
                return False

    @classmethod
    def revert(cls, file_path):
        """
        Revert a file.  Automatically tries to find the workspace for the files
        """
        p4con = connect()
        file_info = Workspace.find(file_path, auto_add=False)
        try:
            p4con.client = file_info["workspace_client"]
            p4con.run("revert", file_path)
        except P4.P4Exception as e:
            if "file(s) not opened on this client." not in str(e):
                raise e

    @classmethod
    def is_latest_revision(cls, file_name, record=None):
        file_report = record if record is not None else Workspace.find(file_name, auto_add=False)
        try:
            if isinstance(file_report, list):
                for report in file_report:
                    if "headAction" in report:
                        if report["headAction"] != "delete":
                            if report["haveRev"] != report["headRev"]:
                                return False
            if isinstance(file_report, dict):
                if "headAction" in file_report:
                    if file_report["headAction"] != "delete":
                        if file_report["haveRev"] != file_report["headRev"]:
                            return False
            else:
                if file_report["Unresolved"] is True:
                    return False
                if file_report["haveRev"] != file_report["headRev"]:
                    return False
        except Exception as e:
            raise e
        return True

    @classmethod
    def get_latest(cls, file_name, force=False, safe=False):

        def process(files):
            if isinstance(files, str):
                files = [files]
            res = []
            for f in files:
                f = f.replace("\n", "\\n")
                f = f.replace("\a", "\\a")
                f = process_path(f)
                res.append(f)
            return res

        file_name = process(file_name)

        p4con = connect()
        file_info = Workspace.find(file_name[0], auto_add=False)
        p4con.client = file_info["workspace_client"]

        try:
            if force:
                return p4con.run("sync", "-f", [file_name])
            else:
                if safe:
                    return p4con.run("sync", "-s", [file_name])
                else:
                    return p4con.run("sync", [file_name])
        except Exception as err:
            err_lines = str(err).split("\n")
            for line in err_lines:
                if "[Warning]" in line:
                    try:
                        warning = line.split(" - ")[1]
                        return warning.split("'")[0]
                    except Exception as _:
                        pass
            return err

    @classmethod
    def is_checked_out(cls, file_path, record=None):
        file_info = record if record is not None else Workspace.find(file_path, auto_add=False)
        if file_info:
            return bool(str(file_info["action"].lower()) in ["edit", "add"])
        raise LookupError("Workspace.find() Error, file not on a workspace path?")

    @classmethod
    def file_state(cls, file_path):
        """Return Perforce state for a workspace path, even if the file is missing locally."""
        file_info = Workspace.find(file_path, auto_add=False)
        if not file_info:
            raise LookupError("Workspace.find() Error, file not on a workspace path?")
        if file_info.get("workspace_client") == "no matching client found":
            raise LookupError(
                f"No matching Perforce client for file: {file_path}"
            )
        if file_info.get("workspace_root") == "no matching workspace found":
            raise LookupError(
                f"No matching Perforce workspace for file: {file_path}"
            )

        p4con = connect(search_path=file_path)
        p4con.client = file_info["workspace_client"]
        try:
            fstat = p4con.run("fstat", process_path(file_path))
        except P4.P4Exception as error:
            errors = "\n".join(p4con.errors) or str(error)
            if "no such file(s)" not in errors:
                raise
            fstat = []

        if fstat:
            file_info.update(fstat[0])
        file_info.setdefault("action", "")
        file_info.setdefault("haveRev", 0)
        file_info.setdefault("headRev", 0)
        file_info.setdefault("otherLock", None)
        return file_info

    @staticmethod
    def _int_state_value(value, default=0):
        try:
            if value in (None, ""):
                return default
            return int(value)
        except (TypeError, ValueError):
            return default

    @classmethod
    def _state_action(cls, file_info):
        return str((file_info or {}).get("action") or "").lower()

    @classmethod
    def _state_has_live_depot_file(cls, file_info):
        if not file_info:
            return False
        head_rev = cls._int_state_value(file_info.get("headRev"))
        if cls._state_action(file_info) == "add" and head_rev <= 0:
            return False
        head_action = str(file_info.get("headAction") or "").lower()
        if head_action in ["delete", "delete/move", "move/delete"]:
            return False
        return head_rev > 0 or (bool(file_info.get("depotFile")) and bool(head_action))

    @classmethod
    def _state_is_latest(cls, file_info):
        if not cls._state_has_live_depot_file(file_info):
            return True
        return cls._int_state_value(file_info.get("haveRev")) == cls._int_state_value(
            file_info.get("headRev")
        )

    @classmethod
    def _state_label(cls, file_path, file_info):
        return (file_info or {}).get("depotFile") or file_path

    @classmethod
    def validate_publish_target(cls, file_path):
        """Fail early if publishing would add over an unsynced depot file."""
        file_info = cls.file_state(file_path)
        action = cls._state_action(file_info)

        if not cls._state_has_live_depot_file(file_info):
            return file_info

        if action == "add":
            raise RuntimeError(
                "Perforce publish target is opened for add, but this file already exists in Perforce.\n"
                f"Local path: {file_path}\n"
                f"Depot file: {cls._state_label(file_path, file_info)}\n"
                "Please revert the add and sync/get latest before publishing."
            )

        if not os.path.exists(file_path):
            raise RuntimeError(
                "Perforce publish target exists in Perforce but is missing from this workspace.\n"
                f"Local path: {file_path}\n"
                f"Depot file: {cls._state_label(file_path, file_info)}\n"
                "Please sync/get latest for the published file before publishing."
            )

        if not cls._state_is_latest(file_info):
            raise RuntimeError(
                "Perforce publish target is not at the latest revision.\n"
                "Local path: {}\n"
                "Depot file: {}\n"
                "Have revision: {}\n"
                "Head revision: {}\n"
                "Please sync/get latest before publishing.".format(
                    file_path,
                    cls._state_label(file_path, file_info),
                    file_info.get("haveRev", "0"),
                    file_info.get("headRev", "0"),
                )
            )

        if file_info.get("otherLock"):
            raise RuntimeError(
                "Perforce publish target is locked by another user.\n"
                "Local path: {}\n"
                "Depot file: {}\n"
                "Lock owner: {}".format(
                    file_path,
                    cls._state_label(file_path, file_info),
                    file_info.get("otherLock"),
                )
            )

        return file_info

    @classmethod
    def check_out_for_publish(cls, file_path, changelist=None, auto_add=True):
        """Check out/add a publish target and raise if Perforce did not open it."""
        cls.validate_publish_target(file_path)
        cls.check_out(
            file_path, changelist=changelist, auto_add=auto_add, auto_update=False
        )

        file_info = cls.file_state(file_path)
        action = cls._state_action(file_info)
        if action in ["edit", "add"]:
            return file_info

        if cls._state_has_live_depot_file(file_info):
            raise RuntimeError(
                "Perforce publish checkout failed; target was not opened for edit.\n"
                "Local path: {}\n"
                "Depot file: {}\n"
                "Current Perforce action: {}".format(
                    file_path,
                    cls._state_label(file_path, file_info),
                    action or "<none>",
                )
            )

        raise RuntimeError(
            "Perforce publish add failed; target was not opened for add.\n"
            "Local path: {}\n"
            "Current Perforce action: {}".format(file_path, action or "<none>")
        )

    @classmethod
    def check_out(cls, file_path, changelist=None, auto_add=False, auto_update=True):
        """
        Uses P4 lib to check out maya scene after gathering necessary information.
        scene can only be checkout if it exist in perforce depot, its not checked out already, and is fully synced to
        head revision also it needs to be saved to disc
        """
        # gets scene file name and initialise variables
        have_rev = -1
        head_rev = -1

        p4con = connect()

        file_info = Workspace.find(file_path, auto_add=False)
        p4con.client = file_info["workspace_client"]

        if isinstance(changelist, dict):
            changelist = int(changelist["Change"])

        log.debug("haveRev : {}".format(file_info["haveRev"]))
        log.debug("headRev : {}".format(file_info["headRev"]))
        log.debug("action : {}".format(file_info["action"]))

        if file_info["action"] == "edit":
            log.debug("Can't checkOut - File is already Checked out")
            if changelist:
                p4con.run("reopen", "-c", changelist, file_path)
            make_file_writable(file_path)
            return

        if file_info["action"] == "add":
            if auto_add:
                cls.add(file_path, changelist=changelist)
            return

        if file_info["action"] == "" and file_info["headRev"] != -1:
            depot_file = file_info.get("depotFile", "")
            if not depot_file:
                log.debug(
                    f"Can't checkOut - File is not in the depot yet: {file_path}"
                )
                return
            cmd_args = []
            if depot_file.lower().endswith(".mb"):
                cmd_args = ["-t", "binary"]
            if head_rev == have_rev:
                cmd_args.extend(["-c", str(changelist), depot_file])
                if changelist:
                    p4con.run("edit", cmd_args)
                    make_file_writable(file_path)
                else:
                    p4con.client = file_info["workspace_client"]
                    p4_check_out(file_path, p4con)
                    make_file_writable(file_path)
            else:
                if auto_update:
                    p4con.run("sync", file_path)
                    p4_check_out(file_path, p4con)
                    make_file_writable(file_path)
                else:
                    log.debug(
                        "Can't Checked Out! - File is not in the latest revision. Sync to latest revision "
                        "before checking out"
                    )

    @classmethod
    def check_in(cls, file_name, comment=""):
        """
            Simply check in the given file
        Args:
            file_name: str - full path to the file
            comment: str - create a changelist with this comment
        Returns: None

        """
        log.debug(f"check_in - file name : {file_name}")

        comment = comment if comment else DEFAULT_COMMENT

        p4con = connect()
        file_info = Workspace.find(file_name, auto_add=True)
        p4con.client = file_info["workspace_client"]

        if file_info["action"] == "edit":
            # if action is set to 'edit' file can be checked in if revision is up to date and scene wasn't
            # modified since last save
            if (
                file_info["haveRev"] == file_info["headRev"]
                and file_info["haveRev"] != -1
            ):
                # if currant file revision is up to date check if scene was modified
                p4_check_in(str(file_name), p4con, comment=str(comment))
            else:
                # if file is not latest revision Can't checkIn. abort operation
                log.warn("file is not the latest revision")
                return

        elif file_info["action"] == "add":
            # if action is set to 'add' file is not part of P4 depot yet but it exist in valid user workspace and
            # can be added if it haven't been modified since last save
            p4_check_in(str(file_name), p4con, comment=str(comment))
        else:
            # if file is not opened for edit find out if its up to date with P4 depot version and ask user if he
            # wants to check it out before saving and checking in
            if (
                file_info["haveRev"] == file_info["headRev"]
                and file_info["haveRev"] != -1
            ):
                p4_check_out(file_name, p4con)
                p4_check_in(str(file_name), p4con, comment=str(comment))
            else:
                log.debug("File is not the latest Revision")
                log.debug(
                    "Error! Cant Check In! - File is not up to date. Sync and reload file first!"
                )


class P4ChangeList:
    @classmethod
    def submit(cls, changelist_data):
        """
        Submit the given changelist
        Args:
            changelist_data: dict

        Returns: None

        """
        if isinstance(changelist_data, dict):
            idx = changelist_data["Change"]
        else:
            raise TypeError(
                "We need the full change list data so we now the client information"
            )

        p4_con = connect()
        p4_con.client = changelist_data["Client"]
        p4_con.run_submit(["-c", f"{idx}"])

    @classmethod
    def create_changelist(cls, message, workspace, force=False):
        """
            Create a change lists.  If a change list with the same description already exists in the workspace
            then that change list will be returned
        Args:
            message: str
            workspace: str - workspace name
            force: bool

        Returns: dict - change list info

        """
        p4_con = connect()

        if isinstance(workspace, dict):
            workspace = workspace.get("workspace_client", "") or workspace.get(
                "client", ""
            )

        p4_con.client = workspace
        existing_change_data = cls.find(message, workspace)
        if existing_change_data and not force:
            return existing_change_data

        desc = {"Description": message, "Change": "new"}
        p4_con.input = desc
        res = p4_con.run("change", "-i")
        if res:
            num = res[0].split()[1]
            return p4_con.fetch_changelist(int(num))
        raise P4.P4Exception("Could not create changelist")

    @classmethod
    def list(cls, workspace, status=None, p4_con=None):
        """
            Get all changelists and optionally filter them by their status
        Args:
            workspace: str - workspace name eg dmoulder_WINDOWS-G2O09QA_Testing
            status: str - pending, submitted, or shelved

        Returns: [dict,]

        """

        #  Unfortunately data isn't consistent from the API when it comes to keys and even the case within the keys.
        #  So we need to sadly call p4 again to make the dict results consistent.

        # p4con.run('changes', *atr)
        # {'status': 'pending', 'changeType': 'public', 'client': 'dmoulder_WINDOWS-G2O09QA_Testing',
        # 'user': 'dmoulder', 'time': '1586435267', 'change': '109', 'desc': 'test_create_change\n'}
        #  ----    verses
        # p4.fetch_changelist(int(num))
        # {'Status': 'pending', 'Description': 'test_create_change\n', 'Client': 'dmoulder_WINDOWS-G2O09QA_Testing',
        # 'User': 'dmoulder', 'Date': '2020/04/09 13:29:04', 'Type': 'public', 'Change': '112'}

        if p4_con is None:
            p4con = connect()
        else:
            p4con = p4_con

        if isinstance(workspace, dict):
            workspace = workspace.get("workspace_client", "") or workspace.get(
                "client", ""
            )

        p4con.client = workspace
        if status:
            atr = ["-c", p4con.client]
            atr.append("-s")
            atr.append(status)
            change_lists = p4con.run("changes", *atr)
            change_lists = [p4con.fetch_changelist(c["change"]) for c in change_lists]
            return change_lists
        else:
            change_lists = p4con.run("changes")
            change_lists = [p4con.fetch_changelist(c["change"]) for c in change_lists]
            return change_lists

    @classmethod
    def get_files_in_changelist(
        cls, description, workspace, status="pending", p4_con=None
    ):
        """
            Given a change list Id get the client file paths of that CL
        Args:
            status: str - pending, submitted, or shelved
            workspace: str - name of workspace, eg dmoulder_WINDOWS-G2O09QA_Main
            description: str

        Returns:

        """

        change = cls.find(description, workspace=workspace, p4_con=p4_con)
        data = cls.get_info(change)
        return data["depotFile"]

    @classmethod
    def find(cls, description, workspace, p4_con=None):
        """
        Find a changelist from the description on this workspace
        Args:
            description: str
            workspace: str

        Returns: {'status': '', 'changeType': '', 'client': ', 'user': '', 'time': '', 'change': '', 'desc': ''}

        """
        change_lists = cls.list(workspace, status="pending", p4_con=p4_con)
        for changelist in change_lists:
            if "Description" in changelist:
                if str(description).lower() in str(changelist["Description"]).lower():
                    return changelist
        return {}

    @classmethod
    def get_info(cls, changelist_data):
        if not isinstance(changelist_data, dict):
            raise TypeError(
                "get_info(changelist_data) requires the full changelist dict"
            )
        connection = connect()
        connect.client = changelist_data["Client"]
        a = connection.run("describe", "-O", str(changelist_data["Change"]))
        a[0].setdefault("depotFile", [])
        return a[0]

    @classmethod
    def new(cls, file_list=None, description="", workspace_client="", p4_con=None):
        """
        Create a new change list and add the given files to it
        Args:
            file_list (list): [str,]
            workspace_client (str): "dmoulder_WINDOWS-G2O09QA_Main"
            description (str): comment for the changelist
        """

        description = description if description else DEFAULT_COMMENT
        if p4_con is None:
            connection = connect()
        else:
            connection = p4_con

        file_info_list = []
        file_list = file_list if not None else []

        if isinstance(workspace_client, dict):
            workspace_root = workspace_client["workspace_root"]
            workspace_client = workspace_client["workspace_client"]
        else:
            workspace_root = workspace_client

        change_list_no = P4ChangeList.create_changelist(
            description, workspace=workspace_client
        )

        if file_list:
            file_info = Workspace.find(file_list[0], auto_add=False)
            client = file_info["workspace_client"]
            for file_name in file_list:
                file_info = Workspace.find(file_name, auto_add=False)
                file_info["fileName"] = file_name
                if file_info["workspace_client"] != client:
                    raise Exception(
                        "Error- specified files belongs to deferent p4 client spaces. Cant create change list"
                    )
                elif file_info["action"] == "add":
                    pass

                else:
                    log.debug(f"checking out file : {file_name}")
                    P4File.check_out(file_name)
                file_info_list.append(file_info)

            connection.client = client

        elif workspace_root != "":
            user_workspaces = Workspace.get_user_workspaces()
            client_found = False
            for workspace in user_workspaces:
                # for each found workspace check is 'root' definition is matching file patch
                for r in workspace:
                    if "Root" in r:
                        _workspaceRoot = workspace["Root"]
                        if workspace_root.lower() in _workspaceRoot.lower():
                            client_found = True
                            connection.client = workspace["client"]
                            client = workspace["client"]
            if not client_found:
                raise LookupError(
                    "Error- specified work space root can't be found in client list"
                )

        # move all the files to the new change list and add any files that need to be added to it
        if change_list_no:
            for file_info in file_info_list:
                if "depotFile" in file_info and "change" in file_info:
                    connection.run(
                        "reopen", ["-c", str(change_list_no), file_info["depotFile"]]
                    )
                if file_info["action"] == "add":
                    P4File.add(file_info["fileName"], changelist=change_list_no)

        return change_list_no


class Workspace:
    @classmethod
    def all_workspace_root_paths(cls):
        """
        returns the root paths of all the user's workspaces
        :return: [str,]
        """
        return [r["Root"].lower() for r in cls.get_user_workspaces()]

    @classmethod
    def get_active_workspace(cls):
        """
        The active ws is set by LaunchPad so we have to match the P4 workspace against that
        :return: {}
        """
        client = os.environ.get("P4CLIENT")
        if not client:
            os.environ.setdefault("P4CLIENT", cls.get_user_workspaces()[0]["client"])
        client = os.environ.get("P4CLIENT")
        try:
            return [ws for ws in cls.get_user_workspaces() if ws["client"] == client][0]
        except IndexError:
            return {"Root": ""}

    @classmethod
    def get_active_workspace_root_path(cls):
        """
        root path of the active perforce workspace
        :return: str
        """
        ws = cls.get_active_workspace()
        return ws["Root"].lower()

    @classmethod
    def get_user_workspaces(cls, filter_by_host=True, p4_con=None):
        """
        Gets the user workspaces on the machine they are working from by using the lib socket.gethostname()
        Args:
            filter_by_host: bool

        Returns: [
                     {'Access': '1586438270',
                      'Backup': 'enable',
                      'Description': 'Created by dmoulder.\n',
                      'Host': 'WINDOWS-G2O09QA',
                      'LineEnd': 'local',
                      'Options': 'noallwrite noclobber nocompress unlocked nomodtime normdir',
                      'Owner': 'dmoulder',
                      'Root': 'D:\\P4\\Streams\\dmoulder_WINDOWS-G2O09QA_Testing',
                      'Stream': '//stream/testing',
                      'SubmitOptions': 'submitunchanged',
                      'Type': 'writeable',
                      'Update': '1586426168',
                      'client': 'dmoulder_WINDOWS-G2O09QA_Testing'}
        ]

        """
        if p4_con is None:
            p4_con = connect()
        if p4_con is None:
            log.error(
                "Failed to establish Perforce connection. Check your Perforce configuration."
            )
            return []
        try:
            if not p4_con.connected():
                p4_con.connect()
        except Exception as e:
            log.error(f"Error connecting to Perforce: {str(e)}")
            return []

        user = p4_con.run("info")
        if not user:
            # If this return False then we might have a bad connection and we need to relog into P4
            user = os.getlogin()
        else:
            user = user[0]["userName"]

        hostname = socket.gethostname()
        discovery_trace(
            "Resolving user workspaces for user=%s host=%s filter_by_host=%s",
            user,
            hostname,
            filter_by_host,
        )
        cache_key = (
            str(getattr(p4_con, "port", "") or ""),
            str(user or ""),
            hostname.lower(),
            bool(filter_by_host),
        )
        cached_workspaces = USER_WORKSPACE_CACHE.get(cache_key)
        if cached_workspaces is not None:
            discovery_trace(
                "Using cached user workspaces for user=%s host=%s count=%d",
                user,
                hostname,
                len(cached_workspaces),
            )
            return [dict(ws) for ws in cached_workspaces]

        if filter_by_host:
            clients = p4_con.run("clients", "-u", user)
            if clients:
                discovery_trace(
                    "Perforce returned %d client(s) for user=%s", len(clients), user
                )
                matching_clients = []
                for r in clients:
                    root = r.get("Root", "")
                    host = r.get("Host", "")
                    root_exists = os.path.exists(root)
                    host_matches = hostname.lower().startswith(host.lower())
                    if all([root_exists, host_matches]):
                        matching_clients.append(r)
                        continue
                    discovery_trace(
                        "Rejecting client=%s root_exists=%s host_matches=%s root=%s host=%s",
                        r.get("client"),
                        root_exists,
                        host_matches,
                        root,
                        host,
                    )
                discovery_trace(
                    "Returning %d host-matched workspace(s)", len(matching_clients)
                )
                USER_WORKSPACE_CACHE[cache_key] = [dict(ws) for ws in matching_clients]
                return [dict(ws) for ws in matching_clients]
            else:
                discovery_trace("No clients returned for user=%s", user)
                USER_WORKSPACE_CACHE[cache_key] = []
                return []
        #                raise Exception("No P4 clients Found for user : {}".format(user))
        else:
            workspaces = [
                r
                for r in p4_con.run("clients", "-u", user)
                if os.path.exists(r["Root"])
            ]
            discovery_trace(
                "Returning %d workspace(s) without host filtering", len(workspaces)
            )
            USER_WORKSPACE_CACHE[cache_key] = [dict(ws) for ws in workspaces]
            return [dict(ws) for ws in workspaces]

    @classmethod
    def find(
        cls, file_name, auto_add=False, changelist_number=None, p4_con=None
    ) -> dict:
        """
        Most important call in the module.  From the given file path this gets all the information needed for the
        P4.connection object to successfully run commands.  Probably the most important is working out which client
        workspace the file is on.
        Args:
            file_name (str): the path to the file
            auto_add (bool): if it's not in perforce, add it?
            changelist_number (int): changelist to add the file to if adding and new file

        Returns: {}

        """

        if p4_con is None:
            p4con = connect()
        else:
            p4con = p4_con

        file_info = {}
        file_info.setdefault("action", "")
        file_info.setdefault("otherLock", None)
        file_info.setdefault("haveRev", 0)
        file_info.setdefault("headRev", 0)

        as_binary = False
        if ".mb" in os.path.splitext(file_name)[1].lower():
            as_binary = True

        # If passed a depot path we need to try and convert it to a local path with the p4 where command
        if file_name.startswith(r"//"):
            # now this can be wrong but it should have the right workspace to match
            if "..." not in file_name:
                local_file_name = process_path(P4File._get_local_file(file_name))
            else:
                # Generally we are searching for a non deleted file on the same client.  We
                # should swap to a files call and return a single result.
                local_file_name = file_name
                files = [n["depotFile"] for n in p4con.run("files", local_file_name)]
                for f in files:
                    d = cls.find(f)
                    if "workspace_client" in d:
                        if d["workspace_client"] == p4con.client:
                            if "headAction" in d:
                                if "delete" not in d["headAction"]:
                                    log.debug("Searching...")
                                    return cls.find(d["depotFile"])
        else:
            local_file_name = process_path(file_name)

        file_name = process_path(file_name)

        # For some reason this is failing to get files every now and then.  It seems to happed when we need to log back into
        # perforce.  I've found that opening maya and running the 'where' p4 cmd kicks things back into life.
        # I think the where cmd is actually a better fit that all the stuff going on in this function.  It's old, and
        # probably needs a clean up.

        """
        Example debug flow:
        import perforce
        config_depot_path = "//.../pipeline_config.json"
        config_info = perforce.Workspace.find(config_depot_path)
        c = perforce.connect()
        c.run("where", config_depot_path)
        """

        user_workspaces = cls.get_user_workspaces(p4_con=p4con)

        for workspace in user_workspaces:
            # for each found workspace check is 'root' definition is matching file patch
            if workspace.get("Root", ""):
                # for r in workspace:
                #     if 'Root' in r:
                workspace_root_path = process_path(workspace["Root"])
                if str(workspace_root_path).lower() in str(local_file_name).lower():
                    # if found matching workspace try to switch p4 client to matching client workspace
                    # then run 'fstat to gather necessary info about file and proceed with checkIn
                    log.debug("Found matching Workspace : {}".format(workspace["client"]))
                    p4con.client = workspace["client"]
                    file_info["workspace_root"] = workspace["Root"]
                    file_info["workspace_client"] = workspace["client"]
                    try:
                        if os.path.exists(local_file_name):
                            if not os.path.isdir(local_file_name):
                                fstat = p4con.run("fstat", local_file_name)
                                if not fstat:
                                    raise Exception("no such file(s)")
                                file_info.update(fstat[0])
                                log.debug(f"fstat result : {fstat}")
                            else:
                                file_info["clientFile"] = local_file_name
                        if changelist_number:
                            p4con.run("reopen", "-c", changelist_number, file_name)
                        return file_info
                    except Exception as err:
                        log.debug(f"fstat returned Exception : {err}")
                        if "no such file(s)" in str(err):
                            # if file path is matching one of the found workspaces but file dont exist in P4 try to
                            # add file to that workspace
                            cmd_args = []
                            if as_binary is True:
                                cmd_args = ["-t", "binary"]
                            if auto_add:
                                cmd = "add"
                                if changelist_number:
                                    cmd_args.extend(
                                        ["-c", str(changelist_number), file_name]
                                    )
                                    p4con.run(cmd, cmd_args)
                                else:
                                    p4con.run(cmd, cmd_args, file_name)
                                log.debug("adding file")
                            file_info["action"] = "add"
                            file_info["haveRev"] = 0
                            file_info["headRev"] = 0
                            return file_info

        log.debug("no matching workspace found")
        file_info["workspace_root"] = "no matching workspace found"
        file_info["workspace_client"] = "no matching client found"
        return file_info


def convert_time_to_date(_time):
    import time

    t = time.localtime(_time)
    seconds = t[5]
    minutes = t[4]
    hours = t[3]
    year = t[0]
    month = t[1]
    day = t[2]
    return (
        str(year)
        + ":"
        + str(month)
        + ":"
        + str(day)
        + "  "
        + str(hours)
        + ":"
        + str(minutes)
        + ":"
        + str(seconds)
    )


def process_path(file_path):
    if file_path:
        file_path = file_path.replace("\\", "/")
    return file_path


def p4_check_in(file_path, c, comment=""):
    comment = comment if comment else DEFAULT_COMMENT
    try:
        stat_ = c.run_fstat(file_path)[0]
        change = c.fetch_change()
        my_files = [stat_["depotFile"]]
        change._files = my_files
        if comment:
            change._description = comment
        c.run_submit(change)
        c.run(
            "change -d",
        )
    except P4.P4Exception as Err:
        log.debug(Err)
        if "no such file(s)" in str(Err):
            p4_add(file_path, c)
            p4_check_in(file_path, c, comment=comment)


_MOVE_FSTAT_FIELDS = ",".join(
    (
        "depotFile",
        "clientFile",
        "headAction",
        "headRev",
        "haveRev",
        "action",
        "change",
        "otherOpen",
        "otherLock",
        "movedFile",
    )
)


def _coerce_move_mapping(mapping):
    if isinstance(mapping, P4MoveMapping):
        return P4MoveMapping(
            process_path(mapping.source), process_path(mapping.destination)
        )
    if isinstance(mapping, Mapping):
        return P4MoveMapping(
            process_path(mapping["source"]),
            process_path(mapping["destination"]),
        )
    if (
        isinstance(mapping, Sequence)
        and not isinstance(mapping, (str, bytes))
        and len(mapping) == 2
    ):
        return P4MoveMapping(process_path(mapping[0]), process_path(mapping[1]))
    raise TypeError(
        "Move mappings must be P4MoveMapping, mapping, or source/destination pair."
    )


def _coerce_move_mappings(mappings):
    normalized = tuple(_coerce_move_mapping(mapping) for mapping in mappings)
    if not normalized:
        raise ValueError("At least one Perforce move mapping is required.")
    for mapping in normalized:
        if not mapping.source or not mapping.destination:
            raise ValueError("Perforce move source and destination paths are required.")
    return normalized


def _move_connection(connection, search_path):
    p4con = connection if connection is not None else connect(search_path=search_path)
    if p4con is None:
        raise RuntimeError("Unable to establish a Perforce connection for native move.")
    connected = getattr(p4con, "connected", None)
    if callable(connected) and not connected():
        p4con.connect()
    return p4con


def _move_fstat(connection, path):
    try:
        result = connection.run("fstat", "-T", _MOVE_FSTAT_FIELDS, process_path(path))
    except P4Exception as error:
        message = _p4_error_message(error).lower()
        if "no such file" in message or "not in client view" in message:
            return {}
        raise
    return result[-1] if result else {}


def _move_state_key(path):
    """Normalise a depot or local path for state lookup."""

    return str(path or "").replace("\\", "/").rstrip("/").casefold()


def list_move_states(root_paths, connection=None):
    """Read the move state of every file below one or more roots.

    One `p4 fstat <root>/...` covers a whole folder, however many files it
    holds. An asset is a folder, so a caller that is about to ask about all of
    its files should ask about the folder once rather than list it and then
    ask again file by file -- which is what `list_versioned_files` followed by
    `preview_moves` used to do, for two round trips and a growing argument
    list where one call answers both.

    Records are keyed by depot path and by client path, so a caller may look
    up either. A root that holds nothing contributes nothing: that is an
    answer, not a failure.
    """

    if isinstance(root_paths, str):
        root_paths = (root_paths,)
    roots = tuple(
        process_path(root).rstrip("/") for root in root_paths if str(root or "").strip()
    )
    if not roots:
        return {}

    p4con = _move_connection(connection, roots[0])
    specs = tuple(root + "/..." for root in roots)
    try:
        result = p4con.run("fstat", "-T", _MOVE_FSTAT_FIELDS, *specs) or []
    except P4Exception as error:
        message = _p4_error_message(error).lower()
        if "no such file" in message or "not in client view" in message:
            return {}
        raise

    states = {}
    for record in result:
        if not isinstance(record, dict):
            continue
        for key in ("clientFile", "depotFile", "path"):
            value = record.get(key)
            if value:
                states[_move_state_key(value)] = record
    return states


def _move_fstats(connection, paths):
    """Read a batch of source/destination states in one server round trip."""

    requested = tuple(process_path(path) for path in paths)
    if not requested:
        return ()
    try:
        result = connection.run("fstat", "-T", _MOVE_FSTAT_FIELDS, *requested) or []
    except P4Exception as error:
        message = _p4_error_message(error).lower()
        if "no such file" in message or "not in client view" in message:
            return tuple({} for _path in requested)
        raise

    records_by_path = {}
    for record in result:
        if not isinstance(record, dict):
            continue
        for key in ("clientFile", "depotFile", "path"):
            value = record.get(key)
            if value:
                records_by_path[_move_state_key(value)] = record
    return tuple(records_by_path.get(_move_state_key(path), {}) for path in requested)


def _tagged_values(record, key):
    values = []
    direct = record.get(key)
    if isinstance(direct, (list, tuple)):
        values.extend(str(value) for value in direct if value)
    elif direct:
        values.append(str(direct))

    for field, value in record.items():
        if field != key and str(field).startswith(key) and value:
            if isinstance(value, (list, tuple)):
                values.extend(str(item) for item in value if item)
            else:
                values.append(str(value))
    return tuple(dict.fromkeys(values))


def _revision(value):
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _has_live_depot_file(record):
    if not record.get("depotFile"):
        return False
    if _revision(record.get("headRev")) <= 0:
        return False
    return str(record.get("headAction", "")).lower() not in (
        "delete",
        "move/delete",
    )


def list_versioned_files(root_path, connection=None, states=None):
    """Return live depot files below ``root_path`` without touching the workspace.

    ``states`` is a folder state dict from `list_move_states`. Given one, this
    answers from it rather than running a second query for a strict subset of
    what has already been read. Liveness is then judged by
    `_has_live_depot_file`, the same predicate `preview_moves` applies to those
    records, rather than by the head action `p4 files` reports -- fstat puts
    the head action in ``headAction`` and reserves ``action`` for a file you
    have open.
    """

    normalized_root = process_path(root_path).rstrip("/")
    if states is not None:
        prefix = _move_state_key(normalized_root) + "/"
        return tuple(
            sorted(
                {
                    str(record["depotFile"])
                    for key, record in states.items()
                    if key.startswith(prefix)
                    and record.get("depotFile")
                    and _has_live_depot_file(record)
                }
            )
        )

    p4con = _move_connection(connection, normalized_root)
    records = p4con.run("files", normalized_root + "/...")
    return tuple(
        str(record["depotFile"])
        for record in records
        if record.get("depotFile")
        and str(record.get("action", record.get("headAction", ""))).lower()
        not in ("delete", "move/delete")
    )


def list_versioned_file_records(root_path, connection=None):
    """Return one batched fstat inventory below ``root_path``.

    The compact records are suitable for read-only UIs that need depot paths,
    client mappings and revision state without issuing one query per file.
    Deleted depot heads are omitted.
    """

    normalized_root = process_path(root_path).rstrip("/")
    p4con = _move_connection(connection, normalized_root)
    fields = "depotFile,clientFile,haveRev,headRev,headAction"
    try:
        records = p4con.run("fstat", "-T", fields, normalized_root + "/...") or ()
    except P4Exception as error:
        message = _p4_error_message(error).lower()
        # "no such file" is an answer: the depot has nothing below this root.
        #
        # "not in client view" is not. It says this client cannot map the path,
        # so the question was never asked -- and returning () reports that as a
        # confident "there are no files in Perforce". The Asset Loader's details
        # panel caches per asset, so one such answer stuck: the Files tab showed
        # every file as absent from the depot for that asset until the entry was
        # evicted, which is why it looked like it broke after a sync and then
        # worked on some assets and not others.
        #
        # Raising costs a visible failure the caller can retry. Being wrong
        # quietly cost the panel's credibility on a tab whose whole job is to
        # say where files are.
        if "no such file" in message:
            return ()
        raise
    return tuple(
        {
            key: record[key]
            for key in ("depotFile", "clientFile", "haveRev", "headRev", "headAction")
            if record.get(key) not in (None, "")
        }
        for record in records
        if isinstance(record, dict) and _has_live_depot_file(record)
    )


def list_pending_move_pairs(
    workspace_path,
    depot_root,
    changelist_description,
    connection=None,
):
    """Return reciprocal native move pairs from one exact pending changelist.

    This is a read-only recovery query. It deliberately scopes changelist
    discovery to the active connection's user and client and never creates a
    changelist when no exact description exists.
    """

    p4con = _move_connection(connection, workspace_path)
    change_args = ["-s", "pending", "-c", str(getattr(p4con, "client", ""))]
    user = str(getattr(p4con, "user", "") or "")
    if user:
        change_args.extend(("-u", user))
    change_args.append("-l")
    pending_changes = p4con.run("changes", *change_args) or ()
    exact_changes = tuple(
        str(change.get("change") or change.get("Change") or "")
        for change in pending_changes
        if str(change.get("desc") or change.get("Description") or "").strip()
        == str(changelist_description).strip()
    )

    normalized_root = process_path(depot_root).rstrip("/")
    pairs = []
    for change in exact_changes:
        if not change:
            continue
        opened = p4con.run("opened", "-c", change, normalized_root + "/...") or ()
        records = {
            str(record.get("depotFile", "")).casefold(): record
            for record in opened
            if record.get("depotFile")
        }
        for destination in opened:
            if str(destination.get("action", "")).lower() != "move/add":
                continue
            destination_path = str(destination.get("depotFile", ""))
            source_path = str(destination.get("movedFile", ""))
            source = records.get(source_path.casefold())
            if source is None:
                source = next(
                    (
                        record
                        for record in opened
                        if str(record.get("action", "")).lower() == "move/delete"
                        and str(record.get("movedFile", "")).casefold()
                        == destination_path.casefold()
                    ),
                    None,
                )
                if source is not None:
                    source_path = str(source.get("depotFile", ""))
            if (
                source is None
                or str(source.get("action", "")).lower() != "move/delete"
                or not source_path
                or not destination_path
            ):
                continue
            pairs.append(P4PendingMovePair(source_path, destination_path, change))

    return tuple(
        sorted(
            pairs,
            key=lambda pair: (
                pair.changelist,
                pair.source.casefold(),
                pair.destination.casefold(),
            ),
        )
    )


def find_versioned_text_files(filespecs, pattern, connection=None):
    """Return depot-head files containing text, without syncing their workspaces."""

    normalized = tuple(
        str(filespec).replace("\\", "/")
        for filespec in filespecs
        if str(filespec or "").strip()
    )
    if not normalized:
        return ()
    if not str(pattern or ""):
        raise ValueError("A Perforce grep pattern is required.")
    search_path = normalized[0].split("...", 1)[0].rstrip("/")
    p4con = _move_connection(connection, search_path)
    try:
        result = p4con.run("grep", "-l", "-e", str(pattern), *normalized) or []
    except P4Exception as error:
        message = _p4_error_message(error).lower()
        if any(
            token in message
            for token in (
                "no file(s)",
                "no such file",
                "no matching",
                "no matches",
            )
        ):
            return ()
        raise

    files = []
    for item in result:
        if isinstance(item, dict):
            depot_file = str(item.get("depotFile") or item.get("path") or "")
        else:
            depot_file = str(item).split(" - line ", 1)[0].strip()
        if "#" in depot_file:
            base, revision = depot_file.rsplit("#", 1)
            if revision.isdigit():
                depot_file = base
        if depot_file:
            files.append(depot_file)
    return tuple(dict.fromkeys(files))


def read_versioned_text(path, revision="head", connection=None, encoding="utf-8"):
    """Read depot text without syncing or otherwise changing the workspace."""

    file_spec = process_path(path)
    if revision and "#" not in file_spec and "@" not in file_spec:
        file_spec = f"{file_spec}#{revision}"
    search_path = re.split(r"[#@]", file_spec, maxsplit=1)[0]
    p4con = _move_connection(connection, search_path)
    response = p4con.run("print", "-q", file_spec)
    chunks = []
    for item in response:
        if isinstance(item, dict):
            continue
        if isinstance(item, bytes):
            chunks.append(item.decode(encoding))
        else:
            chunks.append(str(item))
    return "".join(chunks)


def preview_moves(
    mappings,
    changelist,
    connection=None,
    progress=None,
    depot_only=False,
    states=None,
):
    """Read every source/destination state without mutating Perforce or disk.

    ``depot_only`` selects the unopened-source ``p4 move -r`` workflow. Helix
    still requires every source to be synced at head in the active client; the
    flag only means the caller does not open each source for edit first.

    ``states`` is a folder state dict from `list_move_states`. A caller that
    has already read the source and destination folders passes it here and
    this makes no server call at all -- not even the connection lookup, which
    costs a `p4 where` of its own.
    """

    normalized = _coerce_move_mappings(mappings)
    change = str(changelist)

    source_counts = {}
    destination_counts = {}
    for mapping in normalized:
        source_key = mapping.source.casefold()
        destination_key = mapping.destination.casefold()
        source_counts[source_key] = source_counts.get(source_key, 0) + 1
        destination_counts[destination_key] = (
            destination_counts.get(destination_key, 0) + 1
        )

    reports = []
    if states is None:
        requested = tuple(
            path
            for mapping in normalized
            for path in (mapping.source, mapping.destination)
        )
        p4con = _move_connection(connection, normalized[0].source)
        states = {
            _move_state_key(path): record
            for path, record in zip(requested, _move_fstats(p4con, requested))
            if record
        }
    total = len(normalized)
    for current, mapping in enumerate(normalized, start=1):
        if progress is not None:
            progress(current, total, mapping.source, mapping.destination)
        source = states.get(_move_state_key(mapping.source), {})
        destination = states.get(_move_state_key(mapping.destination), {})
        issues = []

        if not _has_live_depot_file(source):
            issues.append("SOURCE_NOT_VERSIONED")

        have_revision = _revision(source.get("haveRev"))
        head_revision = _revision(source.get("headRev"))
        source_action = str(source.get("action", ""))
        source_change = str(source.get("change", ""))
        destination_action = str(destination.get("action", ""))
        destination_change = str(destination.get("change", ""))
        source_depot = str(source.get("depotFile", ""))
        destination_depot = str(destination.get("depotFile", ""))
        source_moved_file = str(source.get("movedFile", ""))
        destination_moved_file = str(destination.get("movedFile", ""))
        same_change = bool(
            source_change
            and source_change != "0"
            and source_change == destination_change
        )
        expected_change = not change or source_change == change
        staged_pair = bool(
            source_action.lower() == "move/delete"
            and destination_action.lower() == "move/add"
            and same_change
            and expected_change
            and source_depot
            and destination_depot
            and source_moved_file.casefold() == destination_depot.casefold()
            and destination_moved_file.casefold() == source_depot.casefold()
        )

        source_local_path = source.get("clientFile") or mapping.source
        if (
            not staged_pair
            and not str(source_local_path).startswith("//")
            and not os.path.isfile(source_local_path)
        ):
            issues.append("SOURCE_NOT_LOCAL")
        if not staged_pair and head_revision and have_revision != head_revision:
            issues.append("SOURCE_NOT_LATEST")

        if staged_pair:
            pass
        elif depot_only and source_action:
            issues.append("SOURCE_ALREADY_OPEN")
        elif source_action and source_change not in ("", "0", change):
            issues.append("SOURCE_OPEN_IN_OTHER_CHANGELIST")
        elif source_action and source_action.lower() not in ("edit",):
            issues.append(
                "SOURCE_ALREADY_OPEN_FOR_{}".format(
                    source_action.upper().replace("/", "_")
                )
            )

        other_open = _tagged_values(source, "otherOpen")
        other_lock = _tagged_values(source, "otherLock")
        if other_open:
            issues.append("SOURCE_OPEN_BY_OTHER")
        if other_lock:
            issues.append("SOURCE_LOCKED_BY_OTHER")

        if not staged_pair and (
            _has_live_depot_file(destination) or destination.get("action")
        ):
            issues.append("DESTINATION_EXISTS")
        destination_local_path = destination.get("clientFile") or mapping.destination
        if (
            staged_pair
            and not str(destination_local_path).startswith("//")
            and not os.path.isfile(destination_local_path)
        ):
            issues.append("DESTINATION_NOT_LOCAL")
        if (
            staged_pair
            and not str(destination_local_path).startswith("//")
            and os.path.isfile(destination_local_path)
            and not os.access(destination_local_path, os.R_OK)
        ):
            issues.append("DESTINATION_NOT_READABLE")
        if (
            not staged_pair
            and not str(destination_local_path).startswith("//")
            and os.path.exists(destination_local_path)
        ):
            issues.append("DESTINATION_EXISTS_LOCALLY")

        if mapping.source.casefold() == mapping.destination.casefold():
            issues.append("SOURCE_EQUALS_DESTINATION")
        if source_counts[mapping.source.casefold()] > 1:
            issues.append("DUPLICATE_SOURCE")
        if destination_counts[mapping.destination.casefold()] > 1:
            issues.append("DESTINATION_CASE_COLLISION")

        reports.append(
            P4MoveFileReport(
                source=mapping.source,
                destination=mapping.destination,
                source_depot=source_depot,
                destination_depot=destination_depot,
                have_revision=have_revision,
                head_revision=head_revision,
                source_action=source_action,
                source_change=source_change,
                destination_action=destination_action,
                destination_change=destination_change,
                is_staged=staged_pair,
                other_open=other_open,
                other_lock=other_lock,
                issues=tuple(dict.fromkeys(issues)),
            )
        )

    return P4MovePreview(files=tuple(reports), depot_only=bool(depot_only))


def move_files(
    mappings,
    changelist,
    connection=None,
    preview=None,
    depot_only=False,
    progress=None,
):
    """Stage native ``p4 move`` pairs and stop at the first unexpected failure.

    This function deliberately has no integrate/delete, copy/add/delete, submit,
    reopen, revert, or unlock fallback.
    """

    normalized = _coerce_move_mappings(mappings)
    p4con = _move_connection(connection, normalized[0].source)
    if preview is not None:
        depot_only = bool(getattr(preview, "depot_only", depot_only))
    report = preview or preview_moves(
        normalized,
        changelist,
        connection=p4con,
        depot_only=depot_only,
    )
    if not report.is_ready and not report.can_resume:
        return P4MoveExecution(
            unstarted=normalized,
            error="Move preview is blocked: {}".format(", ".join(report.issues)),
        )

    reports_by_source = {item.source.casefold(): item for item in report.files}
    staged = []
    for index, mapping in enumerate(normalized):
        try:
            source_report = reports_by_source[mapping.source.casefold()]
            if source_report.is_staged:
                staged.append(mapping)
                continue
            if depot_only:
                p4con.run(
                    "move",
                    "-r",
                    "-c",
                    str(changelist),
                    mapping.source,
                    mapping.destination,
                )
            elif not source_report.source_action:
                p4con.run("edit", "-c", str(changelist), mapping.source)
            if not depot_only:
                p4con.run(
                    "move",
                    "-c",
                    str(changelist),
                    mapping.source,
                    mapping.destination,
                )
            staged.append(mapping)
            if progress is not None:
                progress(
                    index + 1, len(normalized), mapping.source, mapping.destination
                )
        except Exception as error:
            return P4MoveExecution(
                staged=tuple(staged),
                failed=mapping,
                unstarted=tuple(normalized[index + 1 :]),
                error=_p4_error_message(error),
            )
    return P4MoveExecution(staged=tuple(staged))


def verify_moves(mappings, connection=None, progress=None):
    """Verify each source move/delete and destination move/add pair."""

    normalized = _coerce_move_mappings(mappings)
    p4con = _move_connection(connection, normalized[0].source)
    verifications = []
    for index, mapping in enumerate(normalized, start=1):
        source = _move_fstat(p4con, mapping.source)
        destination = _move_fstat(p4con, mapping.destination)
        source_action = str(source.get("action", "")).lower()
        destination_action = str(destination.get("action", "")).lower()
        issues = []
        if source_action != "move/delete":
            issues.append("SOURCE_NOT_MOVE_DELETE")
        if destination_action != "move/add":
            issues.append("DESTINATION_NOT_MOVE_ADD")
        moved_source = str(destination.get("movedFile", ""))
        source_depot = str(source.get("depotFile", ""))
        if (
            moved_source
            and source_depot
            and moved_source.casefold() != source_depot.casefold()
        ):
            issues.append("MOVE_PAIR_MISMATCH")
        destination_local_path = destination.get("clientFile") or mapping.destination
        if not str(destination_local_path).startswith("//"):
            if not os.path.isfile(destination_local_path):
                issues.append("DESTINATION_NOT_LOCAL")
            elif not os.access(destination_local_path, os.R_OK):
                issues.append("DESTINATION_NOT_READABLE")
        verifications.append(
            P4MoveVerification(
                mapping=mapping,
                source_action=source_action,
                destination_action=destination_action,
                is_valid=not issues,
                issues=tuple(issues),
            )
        )
        if progress is not None:
            progress(index, len(normalized), mapping.source, mapping.destination)
    return tuple(verifications)


def p4_rename_file(file_path, new_name, connection=None, change_list=None):
    """
    Renames a file using the correct perforce way so it's not a delete then add, so perforce doesn't waste space

    Args:
        file_path (str): Full path to the file that needs to be renamed
        new_name (str): The new path or name for the file
        connection (P4.P4, optional): An existing P4 connection object. If None, a new connection will be established.
        change_list (int, optional): Changelist number to use for the operation. If None, the default changelist is used.

    Returns:
        tuple: (success, message) where success is a boolean indicating if the rename was successful
               and message contains details about the operation
    """
    file_path = file_path.replace("\\", "/")
    new_name = new_name.replace("\\", "/")

    p4 = connection if connection else connect(search_path=file_path)

    if not connection or not connection.connected():
        try:
            p4.connect()
        except P4Exception as e:
            return False, f"Error connecting to Perforce: {str(e)}"

    try:
        file_stat = p4.run("fstat", file_path)
        if not file_stat:
            return False, f"File {file_path} not found in Perforce"

        if "action" not in file_stat[0]:
            if change_list:
                p4.run("edit", "-c", str(change_list), file_path)
            else:
                p4.run("edit", file_path)

        cmd = ["integrate", "-f"]
        if change_list:
            cmd.extend(["-c", str(change_list)])
        cmd.extend([file_path, new_name])
        p4.run(cmd)

        delete_cmd = ["delete"]
        if change_list:
            delete_cmd.extend(["-c", str(change_list)])
        delete_cmd.append(file_path)
        p4.run(delete_cmd)

        if not connection:
            p4.disconnect()

        return True, f"Successfully renamed {file_path} to {new_name}"

    except P4Exception as e:
        error_msg = str(e)
        if not connection:
            p4.disconnect()
        return False, f"Error renaming file: {error_msg}"
    except Exception as e:
        if not connection and p4.connected():
            p4.disconnect()
        return False, f"Unexpected error during rename: {str(e)}"


def sync_files(paths, connection=None, progress=None):
    """Sync exact files through the workspace that maps their local paths."""

    normalized = tuple(process_path(path) for path in paths if str(path or "").strip())
    if not normalized:
        return ()
    p4con = connection or connect(search_path=normalized[0])
    results = []
    total = len(normalized)
    for current, path in enumerate(normalized, start=1):
        try:
            results.extend(p4con.run("sync", path) or ())
        except P4Exception as error:
            if "up-to-date" not in _p4_error_message(error).lower():
                raise
        if progress is not None:
            progress(current, total, path)
    return tuple(results)


def p4_sync(path, client=None):
    """
    Runs a Perforce Sync on the given Path
    :path: str
    :client: P4Client for the connection to operate in.
    :return: None
    """
    try:
        connection = connect(client=client, search_path=path) if client else None
        sync_files((path,), connection=connection)
    except P4Exception as e:
        if "up-to-date" in str(e):
            log.info(f"P4 sync result: {str(e)}")
            return None
        log.error(f"P4 sync error: {str(e)}")
        return e


def p4_add(file_path, c):
    if ".mb" in file_path:
        c.run("add", file_path, "-t", "binary")
    else:
        c.run("add", file_path)


def p4_check_out(file_path, c):
    """ """
    try:
        c.run_edit(file_path)
    except P4.P4Exception:
        for e in c.errors:
            if "not on client" in e:
                log.warning(e)


def fetch_existing_changelist(description):
    con = connect()

    # Fetch all pending changelists
    pending_changelists = [
        n for n in con.run_changes("-s", "pending") if n["client"] == con.client
    ]

    # Search for a changelist with the given description
    for changelist in pending_changelists:
        if "desc" in changelist:
            if description.startswith(changelist["desc"].strip()):
                return changelist["change"]
    return -1


def get_or_create_changelist(description):
    con = connect()

    # Search for a changelist with the given description
    existing = fetch_existing_changelist(description)
    if existing != -1:
        return existing

    # If not found, create a new changelist
    change_form = {"Change": "new", "Description": description, "Files": []}
    new_changelist_response = con.run("change", "-i", input=change_form)

    # Extract the changelist number using regex
    match = re.match(r"Change (\d+) created\.", new_changelist_response[0])
    if match:
        return match.group(1)
    else:
        raise ValueError("Failed to extract changelist number from the response.")


def add_folder_to_changelist(folder_path, changelist_description="Renamed Assets"):
    """
    Add the specified folder's content to a new Perforce changelist.

    Parameters:
    - p4: An established P4 connection.
    - folder_path: The path to the folder you want to add.
    - changelist_description: The description for the new changelist.

    Returns:
    The changelist number.
    """

    # Create a new changelist
    con = connect()

    changelist_num = get_or_create_changelist(changelist_description)

    # Add files to the changelist
    con.run_add("-c", changelist_num, f"{folder_path}...")

    return changelist_num


def mark_folder_for_deletion(folder_path, changelist_description="Delete Assets"):
    """
    Mark the specified folder's content in the depot for deletion.

    Parameters:
    - folder_path: The path to the folder you want to delete.
    - changelist_description: The description for the new changelist.

    Returns:
    The changelist number.
    """

    # Library.remove_asset passes None when no description was supplied.
    changelist_description = (changelist_description or "").strip() or "Delete Assets"
    folder = os.fspath(folder_path).replace("\\", "/").rstrip("/")
    if not folder:
        raise ValueError("An asset folder is required for deletion.")
    filespec = folder + "/..."

    con = connect()

    changelist_num = get_or_create_changelist(changelist_description)

    # Sync the folder to ensure you have the latest version
    con.run_sync(filespec)

    # Mark files in the folder for deletion, only if they exist in the depot and workspace
    con.run_delete("-c", changelist_num, filespec)

    return changelist_num


def get_latest_on_folder(folder_path, force=False):
    """
    Sync the latest version of the files in the specified folder from the Perforce depot.

    Parameters:
    - folder_path: The path to the folder you want to sync.
    - force: If True, forces the sync even if the files are already up to date.

    Returns:
    A message indicating the sync status.
    """

    con = connect()

    try:
        # Use 'p4 sync' to get the latest version
        # Add '-f' flag to force the sync if 'force' is set to True
        flags = ["-f"] if force else []
        con.run_sync(*flags, f"{folder_path}...")

        return f"Successfully synced {folder_path} to the latest version."
    except Exception as e:
        return f"Error syncing {folder_path}: {str(e)}"


def checkout_folder_to_changelist(folder_path, changelist_description):
    """
    Checkout the entire folder and its contents into a changelist. If the changelist
    with the provided description doesn't exist, it will be created.

    Parameters:
    - folder_path: The path to the folder you want to checkout.
    - changelist_description: Description of the changelist.

    Returns:
    A message indicating the checkout status.
    """

    con = connect()

    # Get the changelist number (or create a new one if it doesn't exist)
    changelist_number = get_or_create_changelist(changelist_description)

    try:
        # Use 'p4 edit' to check out the folder contents into the changelist
        con.run_edit("-c", changelist_number, f"{folder_path}...")
        return (
            f"Successfully checked out {folder_path} to changelist {changelist_number}."
        )
    except Exception as e:
        return f"Error checking out {folder_path}: {str(e)}"


def checkout_file_to_changelist(path, changelist_description):
    """
    Checkout the entire folder and its contents into a changelist. If the changelist
    with the provided description doesn't exist, it will be created.

    Parameters:
    - path: The path to the file you want to checkout.
    - changelist_description: Description of the changelist.

    Returns:
    A message indicating the checkout status.
    """

    con = connect()

    changelist_number = get_or_create_changelist(changelist_description)

    try:
        con.run_edit("-c", changelist_number, f"{path}")
        return f"Successfully checked out {path} to changelist {changelist_number}."
    except Exception as e:
        return f"Error checking out {path}: {str(e)}"


def has_latest(folder_path):
    """
    Check if the given folder has the latest files from the depot.

    Parameters:
    - folder_path: The path to the folder you want to check. In format: //depot/project/folder/

    Returns:
    True if the folder has the latest files, otherwise False.
    """

    con = connect()

    # Use 'p4 fstat' to get information about file status
    fstat_info = con.run_fstat(f"{folder_path}...")
    if not fstat_info:
        raise ValueError(
            f"Could not retrieve fstat info from folder '{folder_path}' - make sure the folder format is correct"
        )
    if not isinstance(fstat_info, (list, tuple)):
        raise TypeError(
            f"Expected iterable, but got {type(fstat_info)} from run_fstat. {fstat_info}"
        )

    for file_info in fstat_info:
        if "headAction" in file_info:
            # If the file is marked for deletion and has a haveRev key
            if "delete" in file_info["headAction"]:
                if "haveRev" in file_info:
                    return False
            # If the file is not synced at all or at an old revision
            elif (
                "haveRev" not in file_info
                or file_info["headRev"] != file_info["haveRev"]
            ):
                return False
    return True


def find_changelist_containing(substring):
    con = connect()
    # Fetch all pending changelists
    pending_changelists = [
        n for n in con.run_changes("-s", "pending") if n["client"] == con.client
    ]
    found = []
    # Search for a changelist with the given description
    for changelist in pending_changelists:
        if "desc" in changelist:
            desc_len = len(changelist["desc"])  # perforce truncates this
            substring = substring[:desc_len]
            if substring in changelist["desc"].strip() or substring == changelist["desc"]:
                found.append(changelist["change"])
    return found


def get_local_path(depot_path):
    con = connect()
    data = con.run("where", depot_path)
    if data:
        return data[0]["path"]


def files_in_changelist(changelist_id):
    con = connect()
    files_in_changelist = con.run_opened("-c", changelist_id)
    return files_in_changelist


def ensure_trailing_slash(path):
    """Ensure that the given path has a trailing slash."""
    return os.path.join(path, "")


def debug_problematic_changelist(cl_number):
    """
    Debugs a given changelist to identify potential problems preventing submission.

    :param cl_number: The changelist number to debug.
    :param p4: An instance of P4.P4() which is already connected.
    :return: A list of diagnostic messages indicating potential issues.
    """

    diagnostics = []

    p4 = connect()

    locked_files = [f for f in p4.run_opened("-c", cl_number) if "otherOpen" in f]
    if locked_files:
        diagnostics.append("Files locked by other users:")
        for file in locked_files:
            diagnostics.append(f"  {file['depotFile']} locked by {file['otherOpen']}")

    unresolved_files = [f for f in p4.run_resolve("-n", "-c", cl_number)]
    if unresolved_files:
        diagnostics.append("Files that need to be resolved:")
        for file in unresolved_files:
            diagnostics.append(f"  {file['depotFile']}")

    try:
        reconcile_results = p4.run_reconcile("-n", "-c", cl_number)
        if reconcile_results:
            diagnostics.append("Potential discrepancies between workspace and depot:")
            for result in reconcile_results:
                diagnostics.append(f"  {result['depotFile']} ({result['action']})")
    except P4Exception:
        diagnostics.append("Couldn't run p4 reconcile. Might need proper permissions.")

    for file in p4.run_opened("-c", cl_number):
        permissions = p4.run_protects("-m", file["depotFile"])
        if not permissions:
            diagnostics.append(
                f"No explicit permissions for {file['depotFile']}. Check with admin."
            )

    for file in p4.run_opened("-c", cl_number):
        local_path = file["clientFile"]
        if not P4.os.path.exists(local_path):
            diagnostics.append(f"Local file missing or moved: {local_path}")

    return diagnostics


def find_locked_files_in_depot(depot_path):
    """
    Returns a list of files within the given depot path that are checked out by any user.

    :param depot_path: The depot path to search within, e.g. "//depot/my_project/..."
    :param p4: An instance of P4.P4() which is already connected.
    :return: A list of dictionaries, each with details about the locked file.
    """

    p4 = connect()

    if not depot_path.endswith("/..."):
        depot_path += "/..."

    locked_files = []
    try:
        for file in p4.run_opened("-a", depot_path):
            if "action" in file and file["action"] in ["edit", "delete", "add"]:
                locked_files.append(
                    {
                        "depotFile": file["depotFile"],
                        "client": file["client"],
                        "user": file["user"],
                        "action": file["action"],
                    }
                )
    except P4Exception as e:
        print(f"Error querying Perforce: {e}")

    return locked_files


def sync_filtered_files(
    depot_path: str,
    match_mode: str = "endswith",
    match_value: str = ".fbx",
    verbose: bool = True,
    progress_callback: callable = None,
):
    """
    Syncs only files matching a specific pattern under a given depot path.

    Args:
        depot_path (str): The root depot path, e.g. "//depot/root/art/characters/...".
        match_mode (str): One of "endswith", "startswith", "contains".
        match_value (str): The string to match filenames against.
        verbose (bool): If True, prints each synced file.
        progress_callback (callable): Function to call with progress updates.
            Will be called with (current_count, total_count, current_file).

    Returns:
        List[str]: List of client file paths that were synced.
    """
    assert match_mode in ("endswith", "startswith", "contains"), "Invalid match mode."

    con = connect()
    matched_files = []

    try:
        file_list = con.run_files(depot_path)

        def match(file_path: str) -> bool:
            lower_path = file_path.lower()
            value = match_value.lower()
            if match_mode == "endswith":
                return lower_path.endswith(value)
            elif match_mode == "startswith":
                return lower_path.startswith(value)
            elif match_mode == "contains":
                return value in lower_path
            return False

        depot_matches = [f["depotFile"] for f in file_list if match(f["depotFile"])]
        total_files = len(depot_matches)

        for index, depot_file in enumerate(depot_matches):
            if progress_callback:
                progress_callback(index + 1, total_files, depot_file)

            try:
                result = con.run_sync(depot_file)
                if result and "clientFile" in result[0]:
                    matched_files.append(result[0]["clientFile"])
                    if verbose:
                        logging.info(f"Synced: {result[0]['clientFile']}")
                else:
                    if verbose:
                        logging.info(f"Skipped or already synced: {depot_file}")
            except P4Exception as e:
                msg = "\n".join(getattr(e, "errors", []) or [str(e)])
                if "file(s) up-to-date." in msg:
                    if verbose:
                        logging.info(f"Up-to-date (no action): {depot_file}")
                    continue
                raise

    except P4Exception as e:
        logging.exception(e)

    finally:
        con.disconnect()

    return matched_files


def connect_to_perforce(data):
    """
    Given the data from `find_matching_workspace` this will return a perforce connection.
    Args:
        data: [{}, ""]

    Returns: P4.P4() instance
    """

    p4 = new_connection()
    info, port = data

    try:
        p4.port = port
        client = info.get("Client") or info.get("client")
        user = (
            info.get("Owner")
            or info.get("owner")
            or info.get("P4USER")
            or os.environ.get("P4USER")
        )
        if not client:
            log.error("No client found in workspace info: %s", info)
            return None
        if user:
            p4.user = user
        p4.client = client

        p4.connect()

        info = p4.run_info()

    except P4.P4Exception:
        for e in p4.errors:
            log.exception(e)

    # Deliberately not a `finally: return p4`. A return inside finally discards
    # whatever exception is in flight, so anything that is not a P4Exception --
    # a socket timeout in run_info() after connect() succeeded, say -- was
    # swallowed and this handed back a connection as though it had worked.
    # Those now propagate; a P4Exception is still logged and falls through here.
    return p4 if p4.connected() else None


class WorkspaceLocalFiles:
    """Inspect and unsync explicit local files on a dedicated, pinned connection.

    Never deletes depot files or uses forced sync. Callers decide which workshop
    versions are obsolete; this class enforces mapping, have-revision and local
    modification checks. The context owns its connection, safe for a UI worker.
    """

    def __init__(self, root, expected_workspace=None):
        self.root = os.path.normcase(os.path.abspath(root))
        self.expected_workspace = expected_workspace
        self.connection = None

    def __enter__(self):
        with P4_RUNTIME_LOCK:
            shared = connect(search_path=self.root)
            self.connection = new_connection()
            for key in ("port", "user", "client", "charset"):
                value = getattr(shared, key, None)
                if value:
                    setattr(self.connection, key, value)
        try:
            self.connection.connect()
            self.connection.exception_level = 1
            spec = self.connection.fetch_client()
            self.workspace = {
                "port": self.connection.port, "client": self.connection.client,
                "root": spec.get("Root", ""), "stream": spec.get("Stream", ""),
                "view": list(spec.get("View", [])),
                "stream_at_change": spec.get("StreamAtChange", ""),
                "alt_roots": list(spec.get("AltRoots", [])),
            }
            if self.expected_workspace is not None and self.workspace != self.expected_workspace:
                raise RuntimeError("Workspace or stream changed. Scan this library again.")
            if not _connection_maps_path(self.connection, self.root):
                raise RuntimeError("The library is not mapped by the selected workspace.")
            return self
        except Exception:
            self.connection.disconnect()
            raise

    def __exit__(self, *args):
        self.connection.disconnect()

    @staticmethod
    def _key(path):
        return os.path.normcase(os.path.abspath(path))

    def _local_path(self, path):
        path = self._key(path)
        if os.path.commonpath([self.root, path]) != self.root or path == self.root:
            raise ValueError("File is outside the scanned library.")
        if self._key(os.path.realpath(path)) != path or os.path.islink(path):
            raise ValueError("Linked files are kept.")
        if not os.path.isfile(path) or os.stat(path).st_nlink != 1:
            raise ValueError("Missing or hard-linked files are kept.")
        return path

    @staticmethod
    def _spec(path):
        # Literal local files only: never allow a filename to become a filespec.
        if "..." in path or "*" in path:
            raise ValueError("Wildcard filenames are not supported.")
        for source, escaped in (("%", "%25"), ("#", "%23"), ("@", "%40")):
            path = path.replace(source, escaped)
        return path

    def inspect(self, paths, cancelled=lambda: False):
        """Return per-file reasons; only an empty reason means safe to unsync.

        Compare against the revision actually synced, not depot head. P4 diff
        understands text line endings and binary files. Unknown state is kept.
        """
        results = {}
        valid = []
        for path in dict.fromkeys(paths):
            key = self._key(path)
            try:
                valid.append(self._local_path(path))
            except (ValueError, OSError) as error:
                results[key] = str(error)
        for offset in range(0, len(valid), 100):
            if cancelled():
                raise RuntimeError("Scan cancelled; no files removed.")
            batch = valid[offset:offset + 100]
            for path in batch:
                results[path] = "Not synced or Perforce state unavailable"
            specs = [self._spec(path) for path in batch]
            records = self.connection.run("fstat", *specs)
            clean = []
            for record in records:
                if not isinstance(record, dict) or not record.get("clientFile"):
                    continue
                key = self._key(record["clientFile"])
                if key not in batch:
                    continue
                if record.get("action") or record.get("otherOpen") or record.get("otherLock"):
                    results[key] = "Opened or locked in Perforce"
                elif not int(record.get("haveRev", 0)) or not record.get("depotFile"):
                    results[key] = "Not synced from Perforce"
                else:
                    clean.append(key)
            if clean:
                differences = self.connection.run("diff", "-se", *[self._spec(p) for p in clean])
                if self.connection.warnings:
                    # A partial diff is not evidence that the remaining files are clean.
                    continue
                changed = set()
                for record in differences:
                    if not isinstance(record, dict) or not record.get("clientFile"):
                        raise RuntimeError("Unexpected Perforce diff result; no files are eligible.")
                    changed.add(self._key(record["clientFile"]))
                for path in clean:
                    results[path] = "Locally modified" if path in changed else ""
        return results

    def remove(self, paths, cancelled=lambda: False, progress=lambda message: None):
        """Recheck each file, sync it to #none and verify local removal.

        Cancel stops between files. Earlier successes are retained in the result.
        Errors skip the affected file, and never fall back to filesystem deletion.
        """
        results = []
        for path in dict.fromkeys(paths):
            if cancelled():
                break
            result = {"path": path, "removed": False, "bytes": 0, "reason": ""}
            try:
                path = self._local_path(path)
                reason = self.inspect([path])[path]
                if reason:
                    raise RuntimeError(reason)
                size = os.path.getsize(path)
                self.connection.run("sync", "-s", self._spec(path) + "#none")
                if os.path.lexists(path):
                    raise RuntimeError("; ".join(self.connection.warnings) or "Perforce kept the local file")
                result.update(removed=True, bytes=size, reason="Removed locally; depot copy retained")
            except Exception as error:
                result["reason"] = str(error)
            results.append(result)
            progress(os.path.basename(path) + ": " + result["reason"])
        return results
