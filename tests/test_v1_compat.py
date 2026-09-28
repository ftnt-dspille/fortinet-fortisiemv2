"""v2 is the successor to fortinet-fortisiem (v1): a v1 playbook must run on v2
with only the connector name changed.

The contract, pinned here:
  * every v1 6.0.0 operation name exists in v2 (registry AND info.json);
  * every v1 parameter name is still accepted;
  * the ported v1-only operations build the same requests v1 built;
  * shared operations keep v1's result shape where v2 re-implemented them.
"""
from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from conftest import require_connector_module

INFO = json.loads((Path(__file__).resolve().parent.parent / "info.json").read_text())
INFO_OPS = {o["operation"]: o for o in INFO["operations"]}

# fortinet-fortisiem 6.0.0 operations (info.json). Frozen on purpose: this is
# the surface customers' v1 playbooks call.
V1_OPERATIONS = {
    "add_watch_list_entries_to_watch_list_groups", "check_import_task_status",
    "clear_incident", "create_case", "create_lookup_table", "create_task",
    "create_watchlist_group", "delete_lookup_table", "delete_lookup_table_data",
    "delete_watch_list", "delete_watch_list_entry", "execute_api_request",
    "get_all_lookup_tables", "get_associated_events", "get_associated_events_new",
    "get_case_analysts", "get_case_field_schema", "get_device_info",
    "get_devices_details", "get_devices_details_in_address", "get_event_details",
    "get_events_by_query_id", "get_host_context", "get_incident_attributes",
    "get_incident_details", "get_incidents", "get_ip_context", "get_list_cases",
    "get_lookup_table_data", "get_monitored_devices", "get_monitored_organizations",
    "get_org_name_by_org_id", "get_user_context", "get_watch_list_entries_count",
    "get_watch_list_entry", "get_watch_lists", "import_lookup_table_data",
    "incident_comment", "run_report", "search_events", "update_cases",
    "update_incident", "update_lookup_table_data", "update_watch_list_entry",
    "upload_attachment_for_case",
}


def _param_names(op):
    out = set()

    def walk(ps):
        for p in ps or []:
            out.add(p["name"])
            for sub in (p.get("onchange") or {}).values():
                walk(sub)
    walk(op.get("parameters"))
    return out


@pytest.fixture
def ops():
    return require_connector_module("operations")


@pytest.fixture
def compat():
    return require_connector_module("v1_compat")


@pytest.fixture
def config():
    return {"server": "siem.test", "username": "admin", "password": "pw",
            "organization": "Super", "verify_ssl": False}


class _Resp:
    def __init__(self, status=200, body="", ctype="application/json"):
        self.status_code = status
        self.ok = 200 <= status < 300
        self.content = body.encode() if isinstance(body, str) else body
        self.text = body if isinstance(body, str) else body.decode()
        self.headers = {"Content-Type": ctype}
        self.url = "u"
        self.cookies = None

    def json(self):
        return json.loads(self.text)


@pytest.fixture
def wire(monkeypatch):
    """Capture every `requests.request` the REST client makes; answer from a
    route table of (method, path-substring) -> _Resp."""
    import requests
    calls, routes = [], []

    def fake_request(method, url, **kw):
        calls.append({"method": method, "url": url, **kw})
        for (m, frag), resp in routes:
            if m == method and frag in url:
                return resp() if callable(resp) else resp
        raise AssertionError(f"unrouted {method} {url}")
    monkeypatch.setattr(requests, "request", fake_request)
    return calls, routes


# ------------------------------------------------------------------ surface

def test_every_v1_operation_exists_in_v2(ops):
    assert not V1_OPERATIONS - set(ops.operations)
    assert not V1_OPERATIONS - set(INFO_OPS)


def test_every_v1_parameter_is_accepted():
    # Parameters v1 declares that v2's info.json dropped. Each entry is a
    # deliberate rename the code still reads under the v1 name.
    renamed_but_read = {("get_associated_events", "perPage")}
    v1_info = Path(__file__).resolve().parent / "fixtures" / "v1_info_params.json"
    v1 = json.loads(v1_info.read_text())
    v1.pop("_source", None)
    missing = {(op, p) for op, names in v1.items() for p in names
               if p not in _param_names(INFO_OPS[op])} - renamed_but_read
    assert not missing


def test_alias_is_hidden_and_features_are_not():
    assert INFO_OPS["get_associated_events_new"]["visible"] is False
    for name in ("execute_api_request", "create_case", "get_list_cases", "create_task"):
        assert INFO_OPS[name].get("visible", True) is True


# ------------------------------------------------------- ported behaviour

def test_execute_api_request_parses_json_and_prefixes_path(compat, config, wire):
    calls, routes = wire
    routes.append((("POST", "/phoenix/rest/pub/case/analysts"),
                   _Resp(body='{"data": [1]}')))
    out = compat.execute_api_request(config, {
        "endpoint": "rest/pub/case/analysts", "method": "POST",
        "payload": {"a": 1}, "query_params": {"x": "y"}})
    assert out == {"data": [1]}
    assert calls[0]["params"] == {"x": "y"}
    assert json.loads(calls[0]["data"]) == {"a": 1}


def test_execute_api_request_parses_xml(compat, config, wire):
    _, routes = wire
    routes.append((("GET", "/rest/query/progress/7"),
                   _Resp(body="<response><progress>100</progress></response>",
                         ctype="text/xml")))
    out = compat.execute_api_request(config, {"endpoint": "/rest/query/progress/7",
                                              "method": "GET"})
    assert out == {"response": {"progress": "100"}}


@pytest.mark.parametrize("start_body", ['"q-1"', '{"queryId": "q-1"}'],
                         ids=["pre-7.5", "7.5+"])
def test_get_associated_events_new_start_progress_result(compat, config, wire,
                                                         monkeypatch, start_body):
    _, routes = wire
    monkeypatch.setattr(compat.time, "sleep", lambda s: None)
    routes += [
        (("GET", "/triggeringEvents/start"), _Resp(body=start_body)),
        (("GET", "/triggeringEvents/progress/q-1"), _Resp(body='{"progressPct": 100}')),
        (("GET", "/triggeringEvents/result/q-1"),
         _Resp(body='{"data": [{"eventId": "e1"}]}')),
    ]
    out = compat.get_associated_events_new(config, {"incident_id": 5, "perPage": 3})
    assert out == [{"eventId": "e1"}]


def test_create_task_missing_metadata_is_a_connector_error(compat, config):
    from connectors.core.connector import ConnectorError
    with pytest.raises(ConnectorError):
        compat.create_task(config, {"triggeredByUser": "u"})


def test_create_case_normalizes_incident_ids(compat, config, wire):
    calls, routes = wire
    routes.append((("POST", "/rest/pub/case"), _Resp(body='{"id": 9}')))
    compat.create_case(config, {"incidentIds": "1,2", "title": "t", "note": ""})
    body = json.loads(calls[0]["data"])
    assert body == {"incidentIds": ["1", "2"], "title": "t"}


def test_get_list_cases_turns_rows_into_dicts(compat, config, wire):
    calls, routes = wire
    routes.append((("POST", "/rest/query/cmdb"), _Resp(
        body='{"columnNames": ["id", "name"], "data": [[1, "a"], [2, "b"]]}')))
    out = compat.get_list_cases(config, {"selectFields": "id, name", "size": 2})
    assert out["data"] == [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]
    assert json.loads(calls[0]["data"])["selectFields"] == ["id", "name"]
    assert json.loads(calls[0]["data"])["target"] == "CASE"


def test_run_report_sql_mode_sends_clickhouse_sql(ops, config, monkeypatch):
    sent = {}

    def fake_query(obj, payload):
        sent["payload"] = payload
        raise RuntimeError("stop after building the request")
    monkeypatch.setattr(ops, "get_event_query", fake_query)
    from connectors.core.connector import ConnectorError
    with pytest.raises(ConnectorError):
        ops.run_report(config, {"query_type": "SQL Query",
                                "sql_query": "SELECT 1 FROM events"})
    assert "<ClickHouseSQL>" in sent["payload"]
    assert "SELECT 1 FROM events" in sent["payload"]
    with pytest.raises(ConnectorError):
        ops.run_report(config, {"AttrList": "eventType", "cond": "x = 1"})
    assert "<ClickHouseSQL>" not in sent["payload"]


# ------------------------------------------- shared ops keep v1 semantics

def test_get_associated_events_reads_both_page_size_spellings(ops, config, monkeypatch):
    seen = []

    async def fake_async(config, incident_id, size, time_from, time_to):
        seen.append(size)
        return []
    monkeypatch.setattr(ops, "_get_associated_events_async", fake_async)
    ops.get_associated_events(config, {"incident_id": 1, "per_page": 7})
    ops.get_associated_events(config, {"incident_id": 1, "perPage": 4})
    assert seen == [7, 4]


def test_get_incidents_keeps_every_raw_api_field(ops, fake, basic_config, monkeypatch):
    """v1 returned FortiSIEM's /rest/pub/incident JSON as-is (plus derived
    keys). v2 goes through pyfortisiem models; every raw field must survive
    under its API name, or a v1 playbook's `incident.incidentTitle` breaks."""
    conn = require_connector_module("connections")
    original = conn.get_async_client

    def patched(config):
        client = original(config)
        client._client = httpx.AsyncClient(
            verify=False, transport=httpx.MockTransport(fake.handler))
        return client
    monkeypatch.setattr(conn, "get_async_client", patched)
    out = ops.get_incidents(basic_config, {"size": 10})
    raw = fake._incident(123456)
    got = next(i for i in out["data"] if i["incidentId"] == 123456)
    derived = {"incidentSrc", "incidentTarget"}  # v1 parses these too
    for key, value in raw.items():
        assert key in got, key
        if key not in derived and value is not None:
            assert got[key] == value, key


def test_a_non_json_error_body_surfaces_as_itself(compat, config, wire):
    """Live: FortiSIEM answered a non-integer incident id with a plain-text
    body, and the caller saw only "Expecting value: line 1 column 1"."""
    from connectors.core.connector import ConnectorError
    _, routes = wire
    routes.append((("GET", "/triggeringEvents/start"),
                   _Resp(status=400, body="Invalid incident id", ctype="text/plain")))
    with pytest.raises(ConnectorError) as exc:
        compat.get_associated_events_new(config, {"incident_id": "abc"})
    assert "Invalid incident id" in str(exc.value)
    assert "Expecting value" not in str(exc.value)
