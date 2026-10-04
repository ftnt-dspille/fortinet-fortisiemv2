"""Offline tests for the FortiSIEM v2 connector -- no appliance, no network.

Uses httpx.MockTransport to fake the FortiSIEM REST API, then exercises the
connector operations through the pyfortisiem client layer.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from pyfortisiem import AsyncFortiSIEMClient, FortiSIEMError
from pyfortisiem.models import Incident, Event, IncidentWithEvents

from conftest import FakeFortiSIEM


# ---------------------------------------------------------------------------
# helpers -- build an async client wired to the fake transport
# ---------------------------------------------------------------------------

def _make_async_client(fake, config, **kw):
    """Build an AsyncFortiSIEMClient pointed at the fake transport."""
    kw.setdefault("max_concurrency", config.get("max_concurrency", 2))
    kw.setdefault("backoff_factor", 0.0)
    kw.setdefault("poll_interval", 0.0)
    kw.setdefault("transport", httpx.MockTransport(fake.handler))
    if config.get("auth_mode") == "API Key (OAuth2)":
        return AsyncFortiSIEMClient.with_api_key(
            config["server"], config["client_id"], config["client_secret"], **kw
        )
    return AsyncFortiSIEMClient.with_basic_auth(
        config["server"], config["username"], config["password"],
        domain=config.get("organization", "Super"), **kw
    )


# ---------------------------------------------------------------------------
# pyfortisiem client tests (verifying the engine works with our transport)
# ---------------------------------------------------------------------------

class TestAsyncClientBasics:
    async def test_health(self, fake, basic_config):
        async with _make_async_client(fake, basic_config) as fsm:
            assert await fsm.health() == 200

    async def test_list_incidents_typed(self, fake, basic_config):
        async with _make_async_client(fake, basic_config) as fsm:
            incidents = await fsm.list_incidents(status=[0], size=10)
        assert len(incidents) == 2
        assert all(isinstance(i, Incident) for i in incidents)
        assert incidents[0].incident_id == 123456

    async def test_get_incident_and_missing(self, fake, basic_config):
        async with _make_async_client(fake, basic_config) as fsm:
            inc = await fsm.get_incident(123456)
            missing = await fsm.get_incident(999999)
        assert inc is not None and inc.incident_id == 123456
        assert missing is None

    async def test_associated_events_retries_past_503(self, fake, basic_config):
        async with _make_async_client(fake, basic_config) as fsm:
            events = await fsm.get_associated_events(123456, size=5)
        assert fake.flaky_hits >= 2
        assert len(events) == 2
        assert all(isinstance(e, Event) for e in events)

    async def test_incident_with_events_marquee(self, fake, basic_config):
        async with _make_async_client(fake, basic_config) as fsm:
            iwe = await fsm.get_incident_with_events(123456, size=5)
        assert isinstance(iwe, IncidentWithEvents)
        assert iwe.incident_id == 123456
        assert len(iwe.events) == 2

    async def test_bulk_enrichment_respects_concurrency_gate(self, fake, basic_config):
        fake.max_inflight = 0
        async with _make_async_client(fake, basic_config, max_concurrency=2) as fsm:
            bulk = await fsm.list_incidents_with_events(status=[0], size=10, events_per_incident=2)
        assert len(bulk) == 2
        assert all(isinstance(b, IncidentWithEvents) and len(b.events) == 2 for b in bulk)
        assert fake.max_inflight <= 2

    async def test_api_key_mode_mints_once(self, fake, apikey_config):
        async with _make_async_client(fake, apikey_config) as fsm:
            assert fsm.auth_mode == "apikey"
            inc = await fsm.get_incident_with_events(123456, size=5)
            assert inc is not None and len(inc.events) == 2
            assert fake.token_mints == 1
            await fsm.list_incidents(status=[0])
            assert fake.token_mints == 1


# ---------------------------------------------------------------------------
# Field mapping tests
# ---------------------------------------------------------------------------

class TestFieldMapping:
    def test_map_incident_basic(self, sample_incident):
        from fortisiemv2 import field_mapping
        from fortisiemv2.field_mapping import map_incident_to_alert

        alert = map_incident_to_alert(sample_incident)
        assert alert["external_id"] == "123456"
        assert alert["name"] == "Sudden logon volume increase for $computer to root on qa-sys1"
        assert alert["alert_state"] == "Open"
        assert alert["severity"] == "Medium"
        assert alert["category"] == "Security"
        # "Anomaly Detection" is not a member of FortiSOAR's AlertType picklist,
        # and this fixture's "Behavioral Anomaly" sub-category has no counterpart
        # there either, so the mapper clamps to the default. Emitting the raw
        # value instead makes the ingestion playbook's resolveRange miss and the
        # alert POST fail with a picklist 400.
        assert alert["alert_type"] == "Other / Unknown"
        assert alert["alert_type"] in field_mapping.VALID_ALERT_TYPES
        assert alert["source_hostname"] == "qa-sys1"
        assert alert["target_user"] == "root"
        assert alert["dest_hostname"] == "qa-sys1"
        assert alert["rule_name"] == "PH_RULE_USER_MON_SUDDEN_LOGIN_VOLUME_CHANGE"
        assert alert["reporting_device"] == "HOST-10.10.10.10"
        assert alert["reporting_ip"] == "10.10.10.10"

    def test_description_is_styled_and_jinja_safe(self, sample_incident_mitre):
        from fortisiemv2.field_mapping import map_incident_to_alert

        desc = map_incident_to_alert(sample_incident_mitre)["description"]
        # Inline CSS only: the field is sanitised rich text.
        assert "<style" not in desc and "class=" not in desc
        assert "border-radius:999px" in desc  # severity / status / MITRE chips
        assert "MITRE ATT&amp;CK" in desc
        # A brace would be read by FortiSOAR's Jinja when the playbook assigns it.
        assert "{" not in desc and "}" not in desc

    def test_map_incident_mitre(self, sample_incident_mitre):
        from fortisiemv2.field_mapping import map_incident_to_alert

        alert = map_incident_to_alert(sample_incident_mitre)
        assert alert["external_id"] == "789012"
        assert alert["severity"] == "High"
        assert alert["category"] == "Security"
        assert alert["alert_type"] == "Malware"
        assert alert["source_ip"] == "203.0.113.5"
        assert alert["source_hostname"] == "workstation-01"
        assert alert["dest_ip"] == "10.0.0.1"
        assert alert["dest_hostname"] == "dc-01"
        assert alert["target_user"] == "admin"
        assert alert["mitre_technique_id"] == "T1021"
        assert alert["mitre_technique_name"] == "Remote Services"
        assert "T1021" in alert["mitre_technique_ids"]

    def test_parse_attrib_pairs(self):
        from fortisiemv2.field_mapping import parse_attrib_pairs

        result = parse_attrib_pairs("srcIpAddr:10.0.0.1, computer:server01")
        assert result == {"srcIpAddr": "10.0.0.1", "computer": "server01"}

        result = parse_attrib_pairs("user:root,destName:qa-sys1,destIpAddr:10.0.0.1")
        assert result == {"user": "root", "destName": "qa-sys1", "destIpAddr": "10.0.0.1"}

        assert parse_attrib_pairs("") == {}
        assert parse_attrib_pairs(None) == {}
        assert parse_attrib_pairs("no colons here") == {}

    def test_parse_mitre_valid(self):
        from fortisiemv2.field_mapping import parse_mitre

        result = parse_mitre('[{"name": "Remote Services", "techniqueid": "T1021"}]')
        assert result["mitre_technique_id"] == "T1021"
        assert result["mitre_technique_name"] == "Remote Services"

    def test_parse_mitre_empty(self):
        from fortisiemv2.field_mapping import parse_mitre

        assert parse_mitre(None) == {}
        assert parse_mitre("") == {}
        assert parse_mitre("not json") == {}

    def test_map_incident_with_events(self, sample_incident, sample_events):
        from fortisiemv2.field_mapping import map_incident_to_alert

        incident = {**sample_incident, "events": sample_events}
        alert = map_incident_to_alert(incident)
        assert len(alert["evidence"]) == 2
        assert alert["evidence"][0]["eventId"] == "123456-0"

    def test_map_incidents_batch(self, sample_incident, sample_incident_mitre):
        from fortisiemv2.field_mapping import map_incidents_batch

        alerts = map_incidents_batch([sample_incident, sample_incident_mitre])
        assert len(alerts) == 2
        assert alerts[0]["external_id"] == "123456"
        assert alerts[1]["external_id"] == "789012"

    def test_status_mapping(self):
        from fortisiemv2.field_mapping import map_incident_to_alert, INCIDENT_STATUS_MAP

        assert INCIDENT_STATUS_MAP[0] == "Open"
        assert INCIDENT_STATUS_MAP[1] == "Resolved"
        assert INCIDENT_STATUS_MAP[2] == "Closed"
        assert INCIDENT_STATUS_MAP[3] == "Resolved"

    def test_severity_mapping(self):
        from fortisiemv2.field_mapping import SEVERITY_MAP

        assert SEVERITY_MAP["HIGH"] == "High"
        assert SEVERITY_MAP["MEDIUM"] == "Medium"
        assert SEVERITY_MAP["LOW"] == "Low"

    def test_category_mapping(self):
        from fortisiemv2.field_mapping import INCIDENT_CATEGORY_MAP

        assert INCIDENT_CATEGORY_MAP[1] == "Availability"
        assert INCIDENT_CATEGORY_MAP[4] == "Security"

    def test_epoch_ms_to_iso(self):
        from fortisiemv2.field_mapping import _epoch_ms_to_iso

        result = _epoch_ms_to_iso(1708888260000)
        assert result is not None
        assert result.endswith("Z")
        assert _epoch_ms_to_iso(None) is None


# ---------------------------------------------------------------------------
# Ingestion tests
# ---------------------------------------------------------------------------

class TestIngestion:
    def test_ingest_incidents_basic(self, fake, basic_config):
        """Test that ingest_incidents returns mapped alert dicts."""
        from fortisiemv2.ingestion import ingest_incidents
        import fortisiemv2.ingestion as ing_mod

        original_get_async = ing_mod.get_async_client

        def patched_get_async(config):
            client = original_get_async(config)
            client._client = httpx.AsyncClient(
                verify=False, timeout=30,
                limits=httpx.Limits(max_connections=2, max_keepalive_connections=2),
                transport=httpx.MockTransport(fake.handler),
            )
            return client

        ing_mod.get_async_client = patched_get_async
        try:
            params = {
                "from": "2024-01-01T00:00:00.000Z",
                "to": "2024-02-25T00:00:00.000Z",
                "incidentStatus": ["Active"],
                "include_events": True,
                "event_count": 5,
                "size": 10,
            }
            result = ingest_incidents(basic_config, params)
        finally:
            ing_mod.get_async_client = original_get_async

        assert len(result) == 2
        assert result[0]["external_id"] == "123456"
        assert result[0]["alert_state"] == "Open"
        assert result[0]["category"] == "Security"
        assert len(result[0]["evidence"]) > 0


class TestIncidentPagination:
    """`_list_all_incidents` must drain the window, not stop at one page.

    A single /pub/incident call returns at most `size` rows, and the ingestion
    playbook advances its watermark regardless -- so stopping at page one drops
    incidents permanently.
    """

    @staticmethod
    def _fsm(total, page_cap=None):
        class FakeFSM:
            def __init__(self):
                self.calls = []

            async def list_incidents(self, *, size, start=0, **kw):
                self.calls.append({"size": size, "start": start, **kw})
                cap = page_cap or size
                window = list(range(total))[start:start + min(size, cap)]
                return [type("I", (), {"incident_id": i})() for i in window]

        return FakeFSM()

    def _run(self, fsm, size):
        from fortisiemv2.ingestion import _list_all_incidents
        return asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
            _list_all_incidents(fsm, 0, 1, [0], None, size)
        )

    def test_pages_through_entire_window(self):
        fsm = self._fsm(250)
        got = self._run(fsm, 100)
        assert [i.incident_id for i in got] == list(range(250))
        assert [c["start"] for c in fsm.calls] == [0, 100, 200]

    def test_stops_on_short_page(self):
        fsm = self._fsm(150)
        self._run(fsm, 100)
        # 0 -> 100 rows, 100 -> 50 rows (short) -> stop. No wasted third call.
        assert len(fsm.calls) == 2

    def test_exact_multiple_terminates(self):
        """A full final page must be followed by one empty page, then stop."""
        fsm = self._fsm(200)
        got = self._run(fsm, 100)
        assert len(got) == 200
        assert [c["start"] for c in fsm.calls] == [0, 100, 200]

    def test_pages_on_stable_sort_key(self):
        """incidentLastSeen mutates mid-page and both skips and duplicates rows."""
        fsm = self._fsm(150)
        self._run(fsm, 100)
        assert all(c["order_by"] == "incidentId" for c in fsm.calls)
        assert all(c["descending"] is False for c in fsm.calls)

    def test_deduplicates_overlapping_pages(self):
        from fortisiemv2.ingestion import _list_all_incidents

        class Overlapping:
            def __init__(self):
                self.n = 0

            async def list_incidents(self, *, size, start=0, **kw):
                self.n += 1
                ids = [1, 2, 3] if self.n == 1 else [3, 4]
                return [type("I", (), {"incident_id": i})() for i in ids]

        got = asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
            _list_all_incidents(Overlapping(), 0, 1, [0], None, 3)
        )
        assert [i.incident_id for i in got] == [1, 2, 3, 4]

    def test_page_size_clamped_to_server_max(self):
        from fortisiemv2.ingestion import MAX_PAGE_SIZE
        fsm = self._fsm(10)
        self._run(fsm, 99999)
        assert fsm.calls[0]["size"] == MAX_PAGE_SIZE

    def test_run_ceiling_is_enforced(self):
        from fortisiemv2.ingestion import MAX_INCIDENTS_PER_RUN
        fsm = self._fsm(MAX_INCIDENTS_PER_RUN + 500)
        got = self._run(fsm, 1000)
        assert len(got) == MAX_INCIDENTS_PER_RUN

    def test_ignored_start_cannot_loop_forever(self):
        """A server that ignores `start` must not spin the loop indefinitely."""
        from fortisiemv2.ingestion import _list_all_incidents, MAX_INCIDENTS_PER_RUN

        class IgnoresStart:
            async def list_incidents(self, *, size, start=0, **kw):
                return [type("I", (), {"incident_id": i})() for i in range(size)]

        got = asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
            _list_all_incidents(IgnoresStart(), 0, 1, [0], None, 100)
        )
        # Dedupe means nothing new accumulates; the ceiling must break the loop.
        assert len(got) <= MAX_INCIDENTS_PER_RUN


class TestTimeParsing:
    """The playbook emits second-precision UTC; the old parser accepted only
    millisecond precision and read it as local time."""

    @pytest.mark.parametrize("value", [
        "2026-07-01T00:00:00.000Z",
        "2026-07-01T00:00:00Z",
        "2026-07-01T00:00:00",
        "2026-07-01 00:00:00",
    ])
    def test_accepts_all_supported_spellings_as_utc(self, value):
        from fortisiemv2.utils import parse_datetime_to_epoch
        assert parse_datetime_to_epoch(value) == 1782864000

    def test_returns_none_for_garbage(self):
        from fortisiemv2.utils import parse_datetime_to_epoch
        assert parse_datetime_to_epoch("not-a-date") is None
        assert parse_datetime_to_epoch("") is None

    def test_convert_to_ms_handles_second_precision(self):
        from fortisiemv2.operations import convert_time_to_miliseconds
        assert convert_time_to_miliseconds("2026-07-01T00:00:00Z") == 1782864000000
        assert convert_time_to_miliseconds("") == ""

    def test_convert_to_ms_rejects_garbage(self):
        from connectors.core.connector import ConnectorError
        from fortisiemv2.operations import convert_time_to_miliseconds
        with pytest.raises(ConnectorError):
            convert_time_to_miliseconds("not-a-date")


# ---------------------------------------------------------------------------
# Operations registry tests
# ---------------------------------------------------------------------------

class TestOperationsRegistry:
    def test_all_operations_exist(self):
        from fortisiemv2.operations import operations as ops_mod

        assert isinstance(ops_mod, dict)
        assert len(ops_mod) > 30

    def test_legacy_operations_preserved(self):
        from fortisiemv2.operations import operations as ops_mod

        for name in [
            "get_incidents", "get_incident_details", "update_incident",
            "incident_comment", "clear_incident", "get_associated_events",
            "get_monitored_devices", "get_monitored_organizations",
            "run_report", "search_events", "get_event_details",
            "get_watch_lists", "get_all_lookup_tables",
            "get_ip_context", "get_host_context", "get_user_context",
        ]:
            assert name in ops_mod, f"Missing legacy operation: {name}"

    def test_new_mcp_operations_added(self):
        from fortisiemv2.operations import operations as ops_mod

        for name in [
            "get_incidents_by_entity", "get_related_incidents",
            "get_trigger_events", "get_entity_context", "get_entity_reputation",
            "get_iocs_for_incidents", "update_incident_severity",
            "update_incident_resolution", "clear_incident_mcp",
            "get_top_risky_users", "get_top_risky_devices",
            "query_postgres", "query_clickhouse",
        ]:
            assert name in ops_mod, f"Missing MCP operation: {name}"

    def test_ingest_incidents_operation_exists(self):
        from fortisiemv2.operations import operations as ops_mod

        assert "ingest_incidents" in ops_mod
        assert ops_mod["ingest_incidents"] is not None

    def test_credential_management_operations_exist(self):
        from fortisiemv2.operations import operations as ops_mod

        for name in ["list_oauth_credentials", "create_oauth_credential", "revoke_oauth_credential"]:
            assert name in ops_mod
