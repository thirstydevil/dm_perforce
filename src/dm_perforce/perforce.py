__author__ = "david moulder"

import logging
import os
import re
import socket
import stat
import sys
from functools import lru_cache

from P4 import P4Exception

import P4

try:
    import P4API
except ImportError:
    P4API = None

logging.basicConfig()
log = logging.getLogger("dm_perforce")
log.setLevel(logging.INFO)

DEFAULT_COMMENT = "Perforce Check In"
G_CON = None


_ORIGINAL_P4_RUN = P4.P4.run


def patched_run(self, *args, **kargs):
    """Patched run method with session re-authentication."""
    if P4API is None:
        return _ORIGINAL_P4_RUN(self, *args, **kargs)

    context = {}
    resultLogging = True

    if "resultLogging" in kargs:
        resultLogging = False
        del kargs["resultLogging"]

    for (k, v) in list(kargs.items()):
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
        if "Your session has expired" in str(e):
            if self.logger:
                self.logger.warning("Session expired. Attempting re-login.")
            try:
                self.relogin()
                result = P4API.P4Adapter.run(self, *flatArgs)
            except Exception as login_error:
                if self.logger:
                    self.logger.error(f"Re-login failed: {login_error}")
                raise RuntimeError("Perforce session re-login failed.") from login_error
        else:
            for (k, v) in list(context.items()):
                setattr(self, k, v)
            raise e

    if self.logger:
        self.log_messages()

    if resultLogging and self.logger:
        self.logger.debug(result)

    for (k, v) in list(context.items()):
        setattr(self, k, v)

    return result


def relogin(self):
    """
    Re-authenticate to Perforce when the session expires.
    Assumes 'P4PASSWD' is set in the environment or managed securely.
    """
    if self.logger:
        self.logger.info("Attempting to login to Perforce...")

    try:
        self.run("login", input=os.environ.get("P4PASSWD", "").encode("utf-8"))
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


@lru_cache(maxsize=128)
def _auto_configure_connection_for_path(path=None):
    if not path:
        path = get_this_path()

    valid_connections = get_valid_p4_connections()
    if not valid_connections:
        log.warning("No valid Perforce connections available. Check your network/VPN status.")
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
                    log.info(f"Auto-configured connection for {path}: {connection['PORT']}")
                    set_connection_environment(connection)
                    return connection
            except P4Exception:
                pass
            p4.disconnect()
        except Exception as e:
            log.debug(f"Error testing connection {connection.get('PORT')} for path {path}: {str(e)}")
            continue

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

    log.info(f"Client: {client}, connection: {connection}, search_path: {search_path}")

    if search_path:
        data = find_matching_workspace(search_path)
        if data[0] is None:
            connection_data = _auto_configure_connection_for_path(search_path)
            if connection_data:
                return True
            raise Exception("No workspace found")

        p4con = connect_to_perforce(data)
        if p4con:
            os.environ["P4CLIENT"] = p4con.client
            os.environ["P4USER"] = p4con.user
            os.environ["P4PORT"] = str(p4con.port)
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
    for key in keys:
        os.environ[key] = ""


def set_connection_environment(data: dict):
    assert isinstance(data, dict)
    for key, value in data.items():
        log.info("Setting OS Environment Var : {} : {}".format(key, value))
        os.environ[key.upper()] = value


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


@lru_cache()
def get_p4_recent_connections():
    import os
    import xml.etree.ElementTree as ET

    # Form the path to the bookmarks file
    file_path = os.path.join(os.getenv('USERPROFILE'), '.p4qt', 'ApplicationSettings.xml')

    if not os.path.exists(file_path):
        log.warning(f"{file_path} not found to retrieve recent connections")
        return []

    # Parse the XML file
    tree = ET.parse(file_path)
    root = tree.getroot()
    data = []

    # Navigate to RecentConnections
    for elem in root.iter("PropertyList"):
        if 'varName' in elem.attrib and elem.attrib['varName'] == "Connection":
            for sub_elem in elem.iter("StringList"):
                if 'varName' in sub_elem.attrib and sub_elem.attrib['varName'] == "RecentConnections":
                    for string_elem in sub_elem.iter("String"):
                        parts = string_elem.text.replace(" ", "").split(",")
                        parts = [p for p in parts if p]
                        if len(parts) == 3:
                            if all(parts):
                                data.append({"PORT": parts[0], "P4USER": parts[1], "Workspace": parts[2]})
                            else:
                                log.warning(f"Skipping connection : {parts}")
    log.debug("Recent Connections: {}".format(data))
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

    recent_connections = get_p4_recent_connections()
    preferred_port = os.environ.get("P4PORT")
    preferred_user = os.environ.get("P4USER")
    preferred_client = os.environ.get("P4CLIENT")

    def prefer_connection(connections, key, value):
        if value:
            filtered = [c for c in connections if c.get(key) == value]
            if filtered:
                return filtered
        return connections

    recent_connections = prefer_connection(recent_connections, "PORT", preferred_port)
    recent_connections = prefer_connection(recent_connections, "P4USER", preferred_user)
    recent_connections = prefer_connection(recent_connections, "Workspace", preferred_client)

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

        try:
            p4.connect()
            workspace = None
            try:
                workspace = p4.fetch_client(workspace_name)
            except P4.P4Exception as e:
                log.warning(e)

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
                        files = []
                    if files:
                        matching_candidate = candidate
                        break

                if matching_candidate:
                    if workspace:
                        try:
                            p4.client = workspace_name
                            where_info = p4.run("where", matching_candidate)
                        except P4.P4Exception as e:
                            log.error(e)
                            where_info = []
                        if where_info:
                            matching_workspace = workspace
                            port = connection["PORT"]
                            break

                    for ws in Workspace.get_user_workspaces(p4_con=p4):
                        try:
                            p4.client = ws["client"]
                            where_info = p4.run("where", matching_candidate)
                        except P4.P4Exception as e:
                            log.debug(e)
                            continue
                        if where_info:
                            matching_workspace = ws
                            port = connection["PORT"]
                            break
                    if matching_workspace:
                        break
                continue

            local_search_path = process_path(search_path)
            if workspace:
                workspace_root = process_path(workspace.get("Root", ""))
                if workspace_root and workspace_root.lower() in local_search_path.lower():
                    matching_workspace = workspace
                    port = connection["PORT"]
                    break

            for ws in Workspace.get_user_workspaces(p4_con=p4):
                workspace_root = process_path(ws.get("Root", ""))
                if workspace_root and workspace_root.lower() in local_search_path.lower():
                    matching_workspace = ws
                    port = connection["PORT"]
                    break
            if matching_workspace:
                break

        except P4.P4Exception as e:
            log.exception(e)

        finally:
            if not matching_workspace:
                p4.disconnect()

    global G_CON
    G_CON = p4
    return matching_workspace, port


def connect(client=None, force=False, search_path=None):
    """
    returns a P4 connection
    :return:
    """
    global G_CON
    if all([G_CON, force is False]):
        if not G_CON.connected():
            G_CON.port = os.environ.get("P4PORT", G_CON.port)
            G_CON.user = os.environ.get("P4USER", G_CON.user)
            G_CON.client = os.environ.get("P4CLIENT", G_CON.client)
            G_CON.connect()
        return G_CON

    G_CON = new_connection()
    if force:
        reset_connection_caches()

    if search_path:
        success = auto_configure_connection(client, G_CON, search_path)
        if not success:
            # Retry once after cache clear in case VPN/network became available.
            reset_connection_caches()
            success = auto_configure_connection(client, G_CON, search_path)
    else:
        ws = client_from_here(connection=G_CON)
        success = True

    if not success:
        raise ConnectionError(
            "Could not connect to perforce : {}".format(connection_info(G_CON))
        )
    try:
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

    workspace = Workspace.find(search_path, p4_con=None)["workspace_client"]
    log.info("client_from_here : {}".format(search_path))
    log.info("resulting workspace : {}".format(workspace))
    return workspace


@lru_cache()
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


class P4File(object):

    @classmethod
    def info(cls, file_name, auto_add=False, changelist_number=None):
        return Workspace.find(
            file_name=file_name, auto_add=auto_add, changelist_number=changelist_number
        )

    @classmethod
    def exists_in_p4(cls, file_name, include_add=False):
        """
        Check if a file exists in Perforce.

        Args:
            file_name (str): Path to the file to check
            include_add (bool): Whether to consider files marked for 'add' as existing

        Returns:
            tuple: (exists_in_p4, info_dict)
        """
        info = Workspace.find(file_name, auto_add=False)

        if info.get("workspace_client") == "no matching client found" or \
                info.get("workspace_root") == "no matching workspace found":
            return False, info

        mask = ["add", "delete", "delete/move"]
        if include_add:
            mask.pop(0)
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
        log.debug("get_history - file name : %s" % file_name)
        c = new_connection()
        c.connect()
        file_name = process_path(file_name)
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
    def is_locked_by_other(cls, file_name):
        return bool(cls.info(file_name)["otherLock"])

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
                "Found from workspace clientFile {} -> {}".format(depot_file, found)
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
            log.debug("Get local file using WHERE {} -> {}".format(depot_file, found))
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
        log.debug("depot_file - file name : %s" % file_path)
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
        log.info("add - file name : %s" % file_name)
        p4con = connect()

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
    def is_latest_revision(cls, file_name):
        file_report = Workspace.find(file_name, auto_add=False)
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
    def is_checked_out(cls, file_path):
        file_info = Workspace.find(file_path, auto_add=False)
        if file_info:
            return bool(str(file_info["action"].lower()) in ["edit", "add"])
        raise LookupError("Workspace.find() Error, file not on a workspace path?")

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

        log.debug("haveRev : %s" % file_info["haveRev"])
        log.debug("headRev : %s" % file_info["headRev"])
        log.debug("action : %s" % file_info["action"])

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
            cmd_args = []
            if file_info["depotFile"].lower().endswith(".mb"):
                cmd_args = ["-t", "binary"]
            if head_rev == have_rev:
                cmd_args.extend(["-c", str(changelist), file_info["depotFile"]])
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
        log.debug("check_in - file name : %s" % file_name)

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


class P4ChangeList(object):

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
        p4_con.run_submit(["-c", "{}".format(idx)])

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
            if isinstance(file_name, str):
                try:
                    connect(force=True, search_path=file_name)
                except Exception as e:
                    log.debug(f"Auto-configure failed for {file_name}: {e}")
            p4con = connect()
        else:
            p4con = p4_con

        if isinstance(workspace, dict):
            workspace = workspace["workspace_client"]
        p4con.client = workspace
        if status:
            atr = ["-c", p4con.client]
            if status:
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
                    log.debug("checking out file : %s" % file_name)
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


class Workspace(object):

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
            log.error("Failed to establish Perforce connection. Check your Perforce configuration.")
            return []
        try:
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
        if filter_by_host:
            p4_con.connect()
            clients = p4_con.run("clients", "-u", user)
            if clients:
                return [
                    r
                    for r in clients
                    if all(
                        [
                            os.path.exists(r.get("Root", "")),
                            hostname.lower().startswith(r.get("Host", "").lower()),
                        ]
                    )
                ]
            else:
                return []
        #                raise Exception("No P4 clients Found for user : {}".format(user))
        else:
            return [
                r
                for r in p4_con.run("clients", "-u", user)
                if os.path.exists(r["Root"])
            ]

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
        import dm_perforce as perforce
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
                    log.debug("Found matching Workspace : %s" % workspace["client"])
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
                                log.debug("fstat result : %s" % fstat)
                            else:
                                file_info["clientFile"] = local_file_name
                        if changelist_number:
                            p4con.run("reopen", "-c", changelist_number, file_name)
                        return file_info
                    except Exception as err:
                        log.debug("fstat returned Exception : %s" % err)
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
            p4_add(file_path)
            p4_check_in(file_path, comment=comment)


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


def p4_sync(path, client=None):
    """
    Runs a Perforce Sync on the given Path
    :path: str
    :client: P4Client for the connection to operate in.
    :return: None
    """
    if client:
        c = connect(client=client)
    else:
        c = new_connection()
        c.connect()
    try:
        c.run("sync", path)
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

    # Fetch all pending changelists
    pending_changelists = con.run_changes("-s", "pending")

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

    con = connect()

    changelist_num = get_or_create_changelist(changelist_description)

    # Sync the folder to ensure you have the latest version
    con.run_sync(f"{folder_path}...")

    # Mark files in the folder for deletion, only if they exist in the depot and workspace
    con.run_delete("-c", changelist_num, f"{folder_path}...")

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
        response = con.run_sync(*flags, f"{folder_path}...")

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
        response = con.run_edit("-c", changelist_number, f"{folder_path}...")
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
            if substring in changelist["desc"].strip():
                found.append(changelist["change"])
            elif substring == changelist["desc"]:
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
        progress_callback: callable = None
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
        user = info.get("Owner") or info.get("owner") or info.get("P4USER") or os.environ.get("P4USER")
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

    finally:
        if p4.connected():
            return p4
    return None

