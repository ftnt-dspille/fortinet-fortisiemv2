"""
Test fixtures for the FortiSIEM v2 connector.

Provides:
- A ``FakeFortiSIEM`` mock that answers every REST endpoint the connector
  touches, using ``httpx.MockTransport`` -- no appliance, no network.
- Sample incident/event data for field mapping tests.
- Config fixtures for basic-auth and API-key modes.
"""

import json
import os
import sys
import time
import importlib
import importlib.util
import types as _types
from pathlib import Path

import httpx
import pytest

# The connector directory has a hyphen in its name, so we can't import it
# as a normal Python package.  We register it as a virtual package called
# ``fortisiemv2`` so the relative imports (``.constants``, etc.) resolve.
_CONNECTOR_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_CONNECTOR_DIR.parent))

# --- stub FortiSOAR SDK modules so the connector imports standalone ---
if "connectors" not in sys.modules:
    pkg = _types.ModuleType("connectors")
    pkg.__path__ = []
    core = _types.ModuleType("connectors.core")
    core.__path__ = []
    conn_mod = _types.ModuleType("connectors.core.connector")

    class ConnectorError(Exception):
        pass

    class Connector:
        def execute(self, config, operation, params, **kwargs):
            pass

    def get_logger(name):
        import logging
        return logging.getLogger(name)

    conn_mod.ConnectorError = ConnectorError
    conn_mod.Connector = Connector
    conn_mod.get_logger = get_logger

    pkg.core = core
    core.connector = conn_mod
    sys.modules["connectors"] = pkg
    sys.modules["connectors.core"] = core
    sys.modules["connectors.core.connector"] = conn_mod

    # stub connectors.cyops_utilities.builtins (download_file_from_cyops)
    cyops = _types.ModuleType("connectors.cyops_utilities")
    cyops.__path__ = []
    builtins_mod = _types.ModuleType("connectors.cyops_utilities.builtins")
    def download_file_from_cyops(*a, **kw):
        return None
    builtins_mod.download_file_from_cyops = download_file_from_cyops
    cyops.builtins = builtins_mod
    sys.modules["connectors.cyops_utilities"] = cyops
    sys.modules["connectors.cyops_utilities.builtins"] = builtins_mod

# stub integrations.crudhub (make_request)
if "integrations" not in sys.modules:
    integ = _types.ModuleType("integrations")
    integ.__path__ = []
    crudhub = _types.ModuleType("integrations.crudhub")
    def make_request(*a, **kw):
        return None
    crudhub.make_request = make_request
    integ.crudhub = crudhub
    sys.modules["integrations"] = integ
    sys.modules["integrations.crudhub"] = crudhub

# --- register the connector dir as a virtual package "fortisiemv2" ---
_PKG_NAME = "fortisiemv2"
if _PKG_NAME not in sys.modules:
    _virt = _types.ModuleType(_PKG_NAME)
    _virt.__path__ = [str(_CONNECTOR_DIR)]
    _virt.__package__ = _PKG_NAME
    sys.modules[_PKG_NAME] = _virt


def _import_connector_module(name):
    """Import a module from the connector directory as part of the virtual package."""
    full = f"{_PKG_NAME}.{name}"
    if full in sys.modules:
        return sys.modules[full]
    spec = importlib.util.spec_from_file_location(full, _CONNECTOR_DIR / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[full] = mod
    spec.loader.exec_module(mod)
    return mod


# Pre-load the commonly imported modules so tests can import them.
#
# A failure here used to be swallowed whole. That is worse than it sounds:
# `module_from_spec` registers the module in `sys.modules` BEFORE `exec_module`
# runs, so a module that raises partway through is left behind half-built. The
# next `from fortisiemv2.operations import <name>` then finds that shell and
# reports a missing NAME -- e.g. "cannot import name 'list_oauth_credentials'"
# for a function that is plainly defined -- when the real cause was a missing
# dependency several imports earlier. Drop the shell and keep the reason.
_PRELOAD_ERRORS: dict[str, Exception] = {}
for _mod in ["constants", "attributes_list", "connections", "utils", "schema",
             "field_mapping", "ingestion", "operations"]:
    try:
        _import_connector_module(_mod)
    except Exception as exc:  # noqa: BLE001 - recorded and re-raised on use
        _PRELOAD_ERRORS[_mod] = exc
        sys.modules.pop(f"{_PKG_NAME}.{_mod}", None)


def preload_error(module: str) -> Exception | None:
    """The exception that stopped ``module`` importing, if it did not import."""
    return _PRELOAD_ERRORS.get(module)


def require_connector_module(module: str):
    """Return a pre-loaded connector module, or fail naming the real cause."""
    import pytest

    exc = _PRELOAD_ERRORS.get(module)
    if exc is not None:
        pytest.fail(f"{module} could not be imported: {type(exc).__name__}: {exc}")
    return sys.modules[f"{_PKG_NAME}.{module}"]


# ---------------------------------------------------------------------------
# Sample data (anonymized, realistic shapes from a live FortiSIEM appliance)
# ---------------------------------------------------------------------------

SAMPLE_INCIDENT = {
    "incidentId": 123456,
    "incidentTitle": "Sudden logon volume increase for $computer to root on qa-sys1",
    "incidentStatus": 0,
    "eventSeverity": 7,
    "eventSeverityCat": "MEDIUM",
    "phIncidentCategory": 4,
    "phSubIncidentCategory": "Behavioral Anomaly",
    "incidentFirstSeen": 1708801860000,
    "incidentLastSeen": 1708888260000,
    "incidentSrc": "computer:qa-sys1",
    "incidentTarget": "user:root,destName:qa-sys1",
    "incidentRptDevName": "HOST-10.10.10.10",
    "incidentRptIp": "10.10.10.10",
    "incidentDetail": "",
    "eventType": "PH_RULE_USER_MON_SUDDEN_LOGIN_VOLUME_CHANGE",
    "eventName": "Sudden Increase in User Login Volume",
    "customer": "TCL",
    "count": 2,
    "incidentReso": 1,
    "attackTechnique": None,
}

SAMPLE_INCIDENT_MITRE = {
    "incidentId": 789012,
    "incidentTitle": "Suspicious PowerShell execution detected",
    "incidentStatus": 0,
    "eventSeverity": 9,
    "eventSeverityCat": "HIGH",
    "phIncidentCategory": 4,
    "phSubIncidentCategory": "Malware Activity",
    "incidentFirstSeen": 1708900000000,
    "incidentLastSeen": 1708900600000,
    "incidentSrc": "srcIpAddr:203.0.113.5,computer:workstation-01",
    "incidentTarget": "destIpAddr:10.0.0.1,destName:dc-01,user:admin",
    "incidentRptDevName": "HOST-10.0.0.1",
    "incidentRptIp": "10.0.0.1",
    "incidentDetail": "PowerShell encoded command execution detected",
    "eventType": "PH_RULE_MALWARE_POWERSHELL_ENCODED",
    "eventName": "PowerShell Encoded Command Execution",
    "customer": "TCL",
    "count": 1,
    "incidentReso": 1,
    "attackTechnique": '[{"name": "Remote Services", "techniqueid": "T1021"}]',
}

SAMPLE_EVENT = {
    "eventId": "123456-0",
    "eventType": "PH_RULE_USER_MON_SUDDEN_LOGIN_VOLUME_CHANGE",
    "eventName": "Sudden Increase in User Login Volume",
    "eventSeverity": 5,
    "eventSeverityCat": "MEDIUM",
    "srcIpAddr": "203.0.113.10",
    "destIpAddr": "10.0.0.1",
    "hostName": "host-123456",
    "user": "alice",
    "phRecvTime": 1708888260000,
}

SAMPLE_EVENTS = [SAMPLE_EVENT, {**SAMPLE_EVENT, "eventId": "123456-1"}]


# ---------------------------------------------------------------------------
# FakeFortiSIEM -- a stateful mock of the REST surface
# ---------------------------------------------------------------------------

class FakeFortiSIEM:
    """Mock of the /phoenix/rest endpoints that the connector touches."""

    def __init__(self):
        self.flaky_hits = 0
        self.token_mints = 0
        self.progress_hits = {}
        self.request_count = 0
        self.max_inflight = 0
        self._inflight = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.request_count += 1
        self._inflight += 1
        self.max_inflight = max(self.max_inflight, self._inflight)
        try:
            return self._route(request)
        finally:
            self._inflight -= 1

    def _route(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        qs = dict(request.url.params)

        if path.endswith("/pub/security/oauth/token"):
            self.token_mints += 1
            return httpx.Response(200, json={"access_token": "fake-bearer-xyz", "expiresIn": 1440})

        authz = request.headers.get("authorization", "")
        if not authz:
            return httpx.Response(401, text="no auth")

        if path.endswith("/system/health/summary"):
            return httpx.Response(200, json=[{"name": "Super", "id": 1, "version": "8.0.0"}])

        if path.endswith("/rest/pub/incident") and request.method == "POST":
            body = json.loads(request.content or b"{}")
            filters = body.get("filters", {})
            if "incidentId" in filters:
                iid = filters["incidentId"][0]
                if iid == 999999:
                    return httpx.Response(200, json={"data": []})
                return httpx.Response(200, json={"data": [self._incident(iid)]})
            return httpx.Response(200, json={
                "data": [self._incident(i) for i in (123456, 789012)],
                "pages": 1, "total": 2, "queryId": "q-test",
            })

        if path.endswith("/triggeringEvents") and "/start" not in path:
            self.flaky_hits += 1
            if self.flaky_hits == 1:
                return httpx.Response(503, text="not ready")
            iid = int(qs.get("incidentId", 0))
            return httpx.Response(200, json={"data": self._events(iid, 2)})

        if path.endswith("/triggeringEvents/start"):
            iid = qs.get("incidentId", "0")
            return httpx.Response(200, json={"queryId": f"q-{iid}"})

        if "/triggeringEvents/progress/" in path:
            qid = path.rsplit("/", 1)[-1]
            self.progress_hits[qid] = self.progress_hits.get(qid, 0) + 1
            pct = 100 if self.progress_hits[qid] >= 2 else 50
            return httpx.Response(200, json={"progressPct": pct})

        if "/triggeringEvents/result/" in path:
            qid = path.rsplit("/", 1)[-1]
            iid = int(qid.split("-")[-1])
            return httpx.Response(200, json={"data": self._events(iid, 3)})

        if "/query/events/" in path:
            return httpx.Response(200, json={
                "@queryId": "q-1", "@totalCount": "2",
                "data": self._events(1, 2),
            })

        return httpx.Response(404, text=f"unhandled: {request.method} {path}")

    @staticmethod
    def _incident(iid: int) -> dict:
        if iid == 789012:
            return SAMPLE_INCIDENT_MITRE.copy()
        return SAMPLE_INCIDENT.copy()

    @staticmethod
    def _events(iid: int, n: int) -> list[dict]:
        return [{**SAMPLE_EVENT, "eventId": f"{iid}-{k}"} for k in range(n)]


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def fake():
    return FakeFortiSIEM()


@pytest.fixture
def mock_transport(fake):
    return httpx.MockTransport(fake.handler)


@pytest.fixture
def basic_config():
    return {
        "server": "siem.test:443",
        "username": "admin",
        "password": "pw",
        "organization": "Super",
        "verify_ssl": False,
        "auth_mode": "Basic Auth",
        "max_concurrency": 2,
    }


@pytest.fixture
def apikey_config():
    return {
        "server": "siem.test:443",
        "client_id": "test-client-id",
        "client_secret": "test-client-secret",
        "organization": "Super",
        "verify_ssl": False,
        "auth_mode": "API Key (OAuth2)",
        "max_concurrency": 2,
    }


@pytest.fixture
def sample_incident():
    return SAMPLE_INCIDENT.copy()


@pytest.fixture
def sample_incident_mitre():
    return SAMPLE_INCIDENT_MITRE.copy()


@pytest.fixture
def sample_events():
    return [e.copy() for e in SAMPLE_EVENTS]


def _live_env_present():
    """True if a FortiSIEM host is configured, without skipping the test.

    ``_base_live_config`` calls ``pytest.skip`` when nothing is set, which is
    right for a per-test fixture but fatal in a session-scoped autouse one.
    """
    _env_file = Path(__file__).resolve().parent.parent.parent / "fsr-playbook-builder" / ".env.fortisiem"
    if not os.environ.get("FSM_HOST") and not os.environ.get("FSM_SERVER") and _env_file.exists():
        _load_env_file(_env_file)
    return bool(os.environ.get("FSM_HOST") or os.environ.get("FSM_SERVER"))


def _base_live_config():
    """Build the live config from env vars, without any OAuth credential.

    Looks for env vars in this priority order:
    1. Already-set FSM_HOST / FSM_USER / FSM_PASS / FSM_DOMAIN (pyfortisiem convention)
    2. FSM_SERVER / FSM_USERNAME / FSM_PASSWORD / FSM_ORGANIZATION (shared .env.fortisiem)

    If neither is set, skips live tests.
    """
    # Try loading from the shared .env.fortisiem if no direct env vars are set
    _env_file = Path(__file__).resolve().parent.parent.parent / "fsr-playbook-builder" / ".env.fortisiem"
    if not os.environ.get("FSM_HOST") and not os.environ.get("FSM_SERVER") and _env_file.exists():
        _load_env_file(_env_file)

    host = os.environ.get("FSM_HOST") or os.environ.get("FSM_SERVER", "")
    if not host:
        pytest.skip("FSM_HOST/FSM_SERVER not set -- live tests require FortiSIEM creds")
    # Strip https:// prefix -- pyfortisiem wants host:port
    if host.startswith("https://"):
        host = host[len("https://"):]
    elif host.startswith("http://"):
        host = host[len("http://"):]

    username = os.environ.get("FSM_USER") or os.environ.get("FSM_USERNAME", "")
    password = os.environ.get("FSM_PASS") or os.environ.get("FSM_PASSWORD", "")
    domain = os.environ.get("FSM_DOMAIN") or os.environ.get("FSM_ORGANIZATION", "Super")
    verify = os.environ.get("FSM_VERIFY_SSL", "false").lower() in ("true", "1", "yes")

    return {
        "server": host,
        "username": username,
        "password": password,
        "organization": domain,
        "client_id": os.environ.get("FSM_CLIENT_ID", ""),
        "client_secret": os.environ.get("FSM_CLIENT_SECRET", ""),
        "verify_ssl": verify,
        "auth_mode": "API Key (OAuth2)" if os.environ.get("FSM_CLIENT_ID") else "Basic Auth",
        # Deliberately not pinned here -- let the connector's own default apply,
        # so the tests exercise the concurrency the shipped code actually uses.
    }


def _auto_credential_enabled():
    return os.environ.get("FSM_AUTO_CREDENTIAL", "true").lower() in ("true", "1", "yes")


# Every credential the suite creates is named with one of these prefixes, so the
# sweep can tell its own litter apart from real credentials. Anything created by
# a test MUST use one of them or it will not be cleaned up.
TEST_CREDENTIAL_PREFIXES = ("pytest_fortisiemv2_", "pytest_mcp_", "fortisiemv2_test_")


def _is_test_credential(cred):
    name = (cred.get("name") or "")
    return name.startswith(TEST_CREDENTIAL_PREFIXES)


def _sweep_test_credentials(cfg, label):
    """Revoke any still-active credential this suite created.

    Belt-and-braces on top of each fixture's own teardown: a hard crash, a
    killed run, or a test that creates a credential and fails before revoking
    all leave a live credential on the appliance. Matches strictly on the test
    name prefixes, so real credentials are never touched.
    """
    from fortisiemv2.operations import list_oauth_credentials, revoke_oauth_credential

    try:
        creds = list_oauth_credentials(cfg, {})
    except Exception as exc:
        print(f"\n  !! could not list credentials for {label} sweep: {exc}")
        return

    stale = [c for c in creds if _is_test_credential(c) and not c.get("revoked")]
    for cred in stale:
        try:
            revoke_oauth_credential(cfg, {"credential_id": str(cred.get("id", ""))})
            print(f"\n  -- {label} sweep revoked leftover credential "
                  f"id={cred.get('id')} name={cred.get('name')!r}")
        except Exception as exc:
            print(f"\n  !! {label} sweep FAILED to revoke id={cred.get('id')}: {exc}")


@pytest.fixture(scope="session", autouse=True)
def _credential_janitor():
    """Sweep leaked test credentials before and after the session.

    The pre-sweep clears litter from an earlier run that died mid-test; the
    post-sweep catches anything this run leaked. Autouse so it protects every
    live run without each test opting in.
    """
    # Must not use _base_live_config() here: it calls pytest.skip() when no host
    # is configured, and skipping from an autouse session fixture would skip the
    # entire suite -- including the offline tests.
    if not _live_env_present():
        yield  # offline-only run; nothing on an appliance to sweep
        return

    cfg = _base_live_config()
    if not cfg.get("username"):
        yield
        return

    _sweep_test_credentials(cfg, "pre-run")
    yield
    _sweep_test_credentials(cfg, "post-run")


@pytest.fixture(scope="session")
def oauth_credential():
    """An OAuth credential for the MCP tests, minted for the run if needed.

    MCP requires an API key, but the shared .env carries only basic auth -- so
    the whole MCP suite used to skip. FortiSIEM can mint one over the basic-auth
    session, so do that once per session and revoke it in teardown rather than
    leaving the tests unrun.

    Yields ``None`` (tests skip) when there is no basic auth to mint with, or
    when FSM_AUTO_CREDENTIAL is turned off. An externally supplied
    FSM_CLIENT_ID/FSM_CLIENT_SECRET always wins and is never revoked.
    """
    cfg = _base_live_config()

    if cfg.get("client_id") and cfg.get("client_secret"):
        yield {"client_id": cfg["client_id"], "client_secret": cfg["client_secret"]}
        return

    if not _auto_credential_enabled() or not cfg.get("username"):
        yield None
        return

    from fortisiemv2.operations import create_oauth_credential, revoke_oauth_credential

    try:
        cred = create_oauth_credential(cfg, {"name": f"pytest_fortisiemv2_{int(time.time())}"})
    except Exception as exc:  # appliance may forbid credential creation
        print(f"\n  !! could not mint an OAuth credential ({exc}); MCP tests will skip")
        yield None
        return

    try:
        yield {"client_id": cred.get("client_id"), "client_secret": cred.get("client_secret")}
    finally:
        # Always revoke, even if a test blew up -- otherwise every run leaves a
        # live credential behind on the appliance.
        try:
            revoke_oauth_credential(cfg, {"credential_id": str(cred.get("id", ""))})
        except Exception as exc:
            print(f"\n  !! FAILED to revoke test credential id={cred.get('id')}: {exc}")


@pytest.fixture
def live_config():
    """Live test config as configured -- basic auth unless the env supplies a key.

    Deliberately does NOT pick up the minted credential: most operations are
    exercised over basic auth in the field, and silently switching every test to
    OAuth would stop covering that path (and break the credential-management
    tests, which need an h5 session). MCP tests take ``mcp_config`` instead.
    """
    return _base_live_config()


@pytest.fixture
def mcp_config(live_config, oauth_credential):
    """Live config with API-key auth, for the MCP tests."""
    if not oauth_credential or not oauth_credential.get("client_id"):
        pytest.skip("no API key available and none could be minted")
    return {
        **live_config,
        "client_id": oauth_credential["client_id"],
        "client_secret": oauth_credential["client_secret"],
        "auth_mode": "API Key (OAuth2)",
    }


def _load_env_file(path):
    """Load a .env file into os.environ (simple key=value parser)."""
    try:
        for line in Path(path).read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, val = line.partition("=")
            key, val = key.strip(), val.strip()
            if key and key not in os.environ:
                os.environ[key] = val
    except OSError:
        pass
