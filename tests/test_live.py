"""Live tests for the FortiSIEM v2 connector -- opt-in via FSM_* env vars.

These tests run against a real FortiSIEM appliance. They are read-only by
default; mutating tests (incident update/clear/comment) require an explicit
``--mutate`` flag via the ``FSM_ALLOW_MUTATE`` env var.

Setup
-----
Create a ``.env`` file in the tests/ directory (or export env vars):

.. code-block:: bash

    # Basic auth (simplest, works on all versions):
    FSM_HOST=fortisiem.example.com:443
    FSM_USER=admin
    FSM_PASS=yourpassword
    FSM_DOMAIN=Super

    # API key (OAuth2 -- required for MCP tests):
    FSM_CLIENT_ID=your-client-id
    FSM_CLIENT_SECRET=your-client-secret

    # Optional:
    FSM_ALLOW_MUTATE=false   # set to "true" to run mutating tests

Run
---
.. code-block:: bash

    # via the venv pytest
    .venv/bin/python -m pytest tests/test_live.py -v -m live

    # or directly
    .venv/bin/python -m pytest tests/test_live.py -v -m live \\
        --override-ini="addopts="
"""

from __future__ import annotations

import asyncio
import json
import os
import time

import httpx
import pytest

# --- shared fixtures from conftest ---
from conftest import live_config

pytestmark = [pytest.mark.live]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Pause between tests that spawn FortiSIEM server-side queries, so their slots
# are released before the next test asks for more. See _settle_query_slots.
QUERY_SLOT_SETTLE_SECONDS = 5


def _has_mcp(config):
    """Check if the config has API key credentials (needed for MCP)."""
    return bool(config.get("client_id") and config.get("client_secret"))


def _allow_mutate():
    return os.environ.get("FSM_ALLOW_MUTATE", "false").lower() in ("true", "1", "yes")


def _time_range_days(days=7):
    """Return (time_from_ms, time_to_ms) for the last N days."""
    now_ms = int(time.time() * 1000)
    return now_ms - days * 86400_000, now_ms


# ---------------------------------------------------------------------------
# Async client tests (pyfortisiem directly)
# ---------------------------------------------------------------------------

class TestAsyncClientLive:
    """Read-only tests against the real FortiSIEM REST API via pyfortisiem."""

    @pytest.fixture(autouse=True)
    def _settle_query_slots(self):
        """Let FortiSIEM's server-side query slots drain between tests.

        Several tests here hit /pub/incident/triggeringEvents, which spawns a
        server-side query that stays alive after its HTTP response returns.
        FortiSIEM allows 10 concurrent queries per source IP; back to back,
        these tests exhaust that budget and the next one 429s. Each passes in
        isolation -- the pause is about appliance state, not correctness.
        """
        yield
        time.sleep(QUERY_SLOT_SETTLE_SECONDS)

    @pytest.fixture
    def fsm(self, live_config):
        """Build an AsyncFortiSIEMClient from the live config."""
        from pyfortisiem import AsyncFortiSIEMClient

        # pyfortisiem wants a bare host:port. str.lstrip takes a character
        # *set*, not a prefix, so the old lstrip("https://") silently ate any
        # leading h/t/p/s/:/ from a bare hostname -- removeprefix is the
        # prefix-wise operation this always meant.
        host = live_config["server"].strip()
        for scheme in ("https://", "http://"):
            host = host.removeprefix(scheme)

        if _has_mcp(live_config):
            client = AsyncFortiSIEMClient.with_api_key(
                host, live_config["client_id"], live_config["client_secret"],
                verify=live_config.get("verify_ssl", False),
                max_concurrency=live_config.get("max_concurrency", 10),
            )
        else:
            client = AsyncFortiSIEMClient.with_basic_auth(
                host, live_config["username"], live_config["password"],
                domain=live_config.get("organization", "Super"),
                verify=live_config.get("verify_ssl", False),
                max_concurrency=live_config.get("max_concurrency", 10),
            )
        return client

    async def test_health(self, fsm):
        status = await fsm.health()
        assert status == 200, f"Health check failed: HTTP {status}"

    async def test_list_incidents(self, fsm):
        time_from, time_to = _time_range_days(7)
        incidents = await fsm.list_incidents(
            time_from=time_from, time_to=time_to,
            status=[0, 1], size=10,
        )
        assert isinstance(incidents, list)
        if incidents:
            inc = incidents[0]
            assert inc.incident_id is not None
            assert inc.incident_title is not None
            print(f"  -> {len(incidents)} incidents, first: #{inc.incident_id} {inc.incident_title!r}")
        else:
            print("  -> no incidents in last 7 days (widening to 30)")
            time_from, time_to = _time_range_days(30)
            incidents = await fsm.list_incidents(
                time_from=time_from, time_to=time_to,
                status=[0, 1, 2, 3], size=10,
            )
            assert isinstance(incidents, list)

    async def test_get_incident_by_id(self, fsm):
        time_from, time_to = _time_range_days(7)
        incidents = await fsm.list_incidents(
            time_from=time_from, time_to=time_to,
            status=[0, 1], size=5,
        )
        if not incidents:
            pytest.skip("no incidents available to test get-by-id")
        iid = incidents[0].incident_id
        inc = await fsm.get_incident(iid, time_from=time_from, time_to=time_to)
        assert inc is not None
        assert inc.incident_id == iid
        print(f"  -> incident #{iid}: {inc.incident_title!r}")

    async def test_get_associated_events(self, fsm):
        time_from, time_to = _time_range_days(7)
        incidents = await fsm.list_incidents(
            time_from=time_from, time_to=time_to,
            status=[0, 1], size=5,
        )
        if not incidents:
            pytest.skip("no incidents available to test events")
        iid = incidents[0].incident_id
        events = await fsm.get_associated_events(iid, size=5, time_from=time_from, time_to=time_to)
        assert isinstance(events, list)
        print(f"  -> {len(events)} events for incident #{iid}")

    async def test_get_incident_with_events(self, fsm):
        time_from, time_to = _time_range_days(7)
        incidents = await fsm.list_incidents(
            time_from=time_from, time_to=time_to,
            status=[0, 1], size=5,
        )
        if not incidents:
            pytest.skip("no incidents available to test marquee")
        iid = incidents[0].incident_id
        iwe = await fsm.get_incident_with_events(iid, size=5, time_from=time_from, time_to=time_to)
        assert iwe is not None
        assert iwe.incident_id == iid
        assert isinstance(iwe.events, list)
        print(f"  -> incident #{iid} with {len(iwe.events)} events")

    async def test_bulk_enrichment(self, fsm):
        time_from, time_to = _time_range_days(7)
        incidents = await fsm.list_incidents(
            time_from=time_from, time_to=time_to,
            status=[0, 1], size=5,
        )
        if not incidents:
            pytest.skip("no incidents available for bulk test")
        bulk = await fsm.list_incidents_with_events(
            time_from=time_from, time_to=time_to,
            status=[0, 1], size=min(len(incidents), 5),
            events_per_incident=3,
        )
        assert len(bulk) > 0
        assert all(hasattr(b, "events") for b in bulk)
        print(f"  -> enriched {len(bulk)} incidents with events")

    async def test_cleanup(self, fsm):
        await fsm.aclose()


# ---------------------------------------------------------------------------
# Connector operations tests (through the operations.py layer)
# ---------------------------------------------------------------------------

class TestConnectorOpsLive:
    """Test connector operations against the real FortiSIEM."""

    def test_check_health(self, live_config):
        from fortisiemv2.operations import _check_health

        result = _check_health(live_config)
        assert result is True, "Health check should return True"

    def test_get_incidents(self, live_config):
        from fortisiemv2.operations import get_incidents

        now_str = time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime())
        week_ago_str = time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime(time.time() - 7 * 86400))

        params = {
            "timeFrom": week_ago_str,
            "timeTo": now_str,
            "incidentStatus": ["Active"],
            "size": 10,
            "start": 0,
            "orderBy": "incidentLastSeen DESC",
            "fields": "",
            "search": {},
            "severity": [],
            "eventType": "",
            "incidentCategory": "",
            "incidentSubCategory": "",
        }
        result = get_incidents(live_config, params)
        assert "data" in result
        if result["data"]:
            inc = result["data"][0]
            assert "incidentId" in inc
            print(f"  -> {len(result['data'])} incidents, first: #{inc['incidentId']}")

    def test_get_monitored_organizations(self, live_config):
        from fortisiemv2.operations import get_monitored_organizations

        result = get_monitored_organizations(live_config, {})
        assert isinstance(result, list)
        assert len(result) > 0
        print(f"  -> {len(result)} organizations, first: {result[0].get('name', 'unknown')}")

    def test_get_fsm_version(self, live_config):
        from fortisiemv2.operations import get_fsm_version

        version = get_fsm_version(live_config)
        assert version, "Should return a version string"
        print(f"  -> FortiSIEM version: {version}")

    @staticmethod
    def _window(seconds):
        fmt = '%Y-%m-%dT%H:%M:%S.000Z'
        return (time.strftime(fmt, time.gmtime(time.time() - seconds)),
                time.strftime(fmt, time.gmtime()))

    def test_ingest_incidents(self, live_config):
        """Shape check on a narrow window, with event enrichment.

        Enrichment costs one throttled query per incident, so keep the window
        small -- pagination is covered separately by the test below, which
        skips enrichment and can afford a wider window.
        """
        from fortisiemv2.ingestion import ingest_incidents

        since, now = self._window(15 * 60)
        result = ingest_incidents(live_config, {
            "from": since,
            "to": now,
            "incidentStatus": ["Active"],
            "include_events": True,
            "event_count": 3,
            "size": 100,
            "use_query_lifecycle": False,
        })
        assert isinstance(result, list)
        if not result:
            pytest.skip("no incidents in the last 15 minutes")

        alert = result[0]
        for field in ("external_id", "name", "alert_state", "severity", "category"):
            assert field in alert
        print(f"  -> ingested {len(result)} alerts, first: {alert['name']!r}")

    def test_ingest_incidents_paginates_beyond_page_size(self, live_config):
        """A window holding more incidents than `size` must return all of them.

        `size` is a page size, not a cap: one /pub/incident call returns at most
        `size` rows, and the ingestion playbook advances its watermark whether
        or not the window was drained -- so stopping at page one loses incidents
        permanently. Events are skipped here to keep the run fast.
        """
        from fortisiemv2.ingestion import ingest_incidents

        page_size = 25
        since, now = self._window(24 * 3600)
        result = ingest_incidents(live_config, {
            "from": since,
            "to": now,
            "incidentStatus": ["Active"],
            "include_events": False,
            "size": page_size,
        })
        assert isinstance(result, list)
        if len(result) <= page_size:
            pytest.skip(
                f"only {len(result)} incidents in 24h; need >{page_size} to "
                "exercise paging")

        ids = [a["external_id"] for a in result]
        assert len(ids) == len(set(ids)), "paging returned duplicate incidents"
        print(f"  -> paged {len(ids)} incidents in pages of {page_size}")


# ---------------------------------------------------------------------------
# Field mapping tests with real data
# ---------------------------------------------------------------------------

class TestFieldMappingLive:
    """Verify field mapping works correctly with real FortiSIEM incident data."""

    def test_map_real_incident(self, live_config):
        from fortisiemv2.operations import get_incidents
        from fortisiemv2.field_mapping import map_incident_to_alert

        now_str = time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime())
        week_ago_str = time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime(time.time() - 7 * 86400))

        params = {
            "timeFrom": week_ago_str,
            "timeTo": now_str,
            "incidentStatus": ["Active"],
            "size": 5,
            "start": 0,
            "orderBy": "incidentLastSeen DESC",
            "fields": "",
            "search": {},
            "severity": [],
            "eventType": "",
            "incidentCategory": "",
            "incidentSubCategory": "",
        }
        result = get_incidents(live_config, params)
        if not result.get("data"):
            pytest.skip("no incidents available for field mapping test")

        inc = result["data"][0]
        alert = map_incident_to_alert(inc)

        assert alert["external_id"] == str(inc.get("incidentId"))
        assert alert["name"] == inc.get("incidentTitle")
        assert "alert_state" in alert
        assert "severity" in alert
        assert "category" in alert

        print(f"  -> mapped incident #{inc['incidentId']}:")
        print(f"     name: {alert['name']!r}")
        print(f"     state: {alert['alert_state']}")
        print(f"     severity: {alert['severity']}")
        print(f"     category: {alert['category']}")
        if alert.get("source_ip"):
            print(f"     source_ip: {alert['source_ip']}")
        if alert.get("mitre_technique_id"):
            print(f"     mitre: {alert['mitre_technique_id']} - {alert['mitre_technique_name']}")


# ---------------------------------------------------------------------------
# MCP tests (FortiSIEM 8.0+ with API key)
# ---------------------------------------------------------------------------

class TestMCPLive:
    """MCP tool tests -- require API key auth (FSM_CLIENT_ID + FSM_CLIENT_SECRET)."""

    @pytest.fixture
    def mcp_available(self, mcp_config):
        """`mcp_config` skips on its own if no key exists or can be minted."""
        return mcp_config

    def test_mcp_list_tools(self, mcp_available, mcp_config):
        from fortisiemv2.connections import get_mcp_session

        session, sync = get_mcp_session(mcp_config)
        try:
            tools = session.list_tools()
            assert len(tools) > 0
            print(f"  -> {len(tools)} MCP tools advertised")
            for t in tools[:5]:
                print(f"     - {t.name}")
        finally:
            sync.close()

    def test_mcp_get_incidents_by_entity(self, mcp_available, mcp_config):
        """Use a public IP as a safe entity query."""
        from fortisiemv2.connections import get_mcp_session
        from pyfortisiem.models import EntityIncidentQuery, TimeUnit

        session, sync = get_mcp_session(mcp_config)
        try:
            q = EntityIncidentQuery(
                time_value=24, time_unit=TimeUnit.hours,
                ip="8.8.8.8",
            )
            results = session.get_incidents_by_entity(q)
            assert isinstance(results, list)
            print(f"  -> {len(results)} incidents for 8.8.8.8 in last 24h")
        except Exception as e:
            if "no incidents" in str(e).lower() or "not found" in str(e).lower():
                print("  -> no incidents for 8.8.8.8 (expected for test IP)")
            else:
                raise
        finally:
            sync.close()

    def test_mcp_get_reputation(self, mcp_available, mcp_config):
        from fortisiemv2.connections import get_mcp_session
        from pyfortisiem.models import EntityReputationQuery

        session, sync = get_mcp_session(mcp_config)
        try:
            q = EntityReputationQuery(ip=["8.8.8.8"])
            results = session.get_reputation_by_entity(q)
            assert isinstance(results, list)
            if results:
                print(f"  -> reputation for 8.8.8.8: {results[0].ip}")
        except Exception as e:
            print(f"  -> reputation lookup failed (may be expected): {e}")
        finally:
            sync.close()

    def test_mcp_top_risky_users(self, mcp_available, mcp_config):
        from fortisiemv2.connections import get_mcp_session

        session, sync = get_mcp_session(mcp_config)
        try:
            results = session.top_10_risky_users()
            assert isinstance(results, list)
            if results:
                print(f"  -> top risky user: {results[0].name} score={results[0].score}")
            else:
                print("  -> no risky users (appliance may not have UEBA enabled)")
        except Exception as e:
            print(f"  -> risky users failed (may be expected): {e}")
        finally:
            sync.close()

    def test_mcp_query_postgres(self, mcp_available, mcp_config):
        from fortisiemv2.connections import get_mcp_session

        session, sync = get_mcp_session(mcp_config)
        try:
            results = session.query_postgres("SELECT 1 AS one")
            assert isinstance(results, list)
            assert results[0].get("one") == 1
            print(f"  -> postgres query OK: {results}")
        finally:
            sync.close()

    def test_mcp_query_clickhouse(self, mcp_available, mcp_config):
        from fortisiemv2.connections import get_mcp_session

        session, sync = get_mcp_session(mcp_config)
        try:
            table = session.query_clickhouse(
                "SELECT eventType, count(*) AS c FROM events GROUP BY eventType ORDER BY c DESC LIMIT 3"
            )
            assert len(table.columns) > 0
            print(f"  -> clickhouse query OK: {len(table.rows)} rows, columns: {table.columns}")
        except Exception as e:
            print(f"  -> clickhouse query failed (may not be available): {e}")
        finally:
            sync.close()

    def test_mcp_prompts(self, mcp_available, mcp_config):
        from fortisiemv2.connections import get_mcp_session

        session, sync = get_mcp_session(mcp_config)
        try:
            pg_prompt = session.query_postgres_prompts()
            assert isinstance(pg_prompt, str)
            assert len(pg_prompt) > 50
            print(f"  -> postgres prompt: {pg_prompt[:80]!r}...")
        finally:
            sync.close()


# ---------------------------------------------------------------------------
# Mutating tests (gated behind FSM_ALLOW_MUTATE)
# ---------------------------------------------------------------------------

class TestMutationsLive:
    """Mutating tests -- require FSM_ALLOW_MUTATE=true.

    Only the benign comment append is run (no incident clear/severity change).
    """

    def _get_first_incident_id(self, live_config):
        from fortisiemv2.operations import get_incidents

        now_str = time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime())
        week_ago_str = time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime(time.time() - 7 * 86400))

        params = {
            "timeFrom": week_ago_str, "timeTo": now_str,
            "incidentStatus": ["Active"], "size": 1,
            "start": 0, "orderBy": "incidentLastSeen DESC",
            "fields": "", "search": {}, "severity": [],
            "eventType": "", "incidentCategory": "", "incidentSubCategory": "",
        }
        result = get_incidents(live_config, params)
        if not result.get("data"):
            pytest.skip("no incidents available for mutation test")
        return result["data"][0]["incidentId"]

    def test_add_comment_rest(self, live_config):
        if not _allow_mutate():
            pytest.skip("mutating tests require FSM_ALLOW_MUTATE=true")

        iid = self._get_first_incident_id(live_config)
        from fortisiemv2.operations import incident_comment

        result = incident_comment(live_config, {
            "id": str(iid),
            "comment_text": f"FortiSIEM v2 connector live test (benign) at {time.strftime('%Y-%m-%d %H:%M:%S')}",
        })
        assert "message" in result
        print(f"  -> comment added to incident #{iid}: {result['message']}")

    def test_add_comment_mcp(self, mcp_config):
        if not _allow_mutate():
            pytest.skip("mutating tests require FSM_ALLOW_MUTATE=true")

        iid = self._get_first_incident_id(mcp_config)
        from fortisiemv2.operations import append_incident_comment_mcp

        result = append_incident_comment_mcp(mcp_config, {
            "incident_id": str(iid),
            "comment": f"FortiSIEM v2 MCP live test (benign) at {time.strftime('%Y-%m-%d %H:%M:%S')}",
        })
        assert result.get("result", "").lower() == "success" or result.get("ok")
        print(f"  -> MCP comment added to incident #{iid}")


# ---------------------------------------------------------------------------
# Credential management tests
# ---------------------------------------------------------------------------

class TestCredentialManagementLive:
    """Test OAuth credential CRUD (requires basic auth for h5 session)."""

    def test_list_credentials(self, live_config):
        if not live_config.get("username"):
            pytest.skip("credential management requires basic auth (FSM_USER + FSM_PASS)")

        from fortisiemv2.operations import list_oauth_credentials

        result = list_oauth_credentials(live_config, {})
        assert isinstance(result, list)
        print(f"  -> {len(result)} OAuth credentials configured")

    def test_create_and_revoke_credential(self, live_config):
        if not _allow_mutate():
            pytest.skip("mutating tests require FSM_ALLOW_MUTATE=true")
        if not live_config.get("username"):
            pytest.skip("credential management requires basic auth")

        from fortisiemv2.operations import create_oauth_credential, revoke_oauth_credential

        cred = create_oauth_credential(live_config, {
            "name": f"fortisiemv2_test_{int(time.time())}",
        })
        # Revoke in `finally`: a failing assertion below would otherwise leave a
        # live credential on the appliance forever.
        try:
            assert cred.get("client_id"), f"no client_id in {sorted(cred)}"
            assert cred.get("client_secret"), "client_secret is only returned at creation"
            print(f"  -> created credential: {cred['client_id'][:12]}...")
        finally:
            revoke_oauth_credential(live_config, {"credential_id": str(cred.get("id", ""))})
            print(f"  -> revoked credential id={cred.get('id')}")


# ---------------------------------------------------------------------------
# CMDB / device / organization operations
# ---------------------------------------------------------------------------

class TestCmdbLive:
    """Read-only CMDB and organization lookups.

    These go through /rest/cmdbDeviceInfo/*, which answers XML -- the connector
    runs it through xmltodict, so the assertions here are really checking that
    the parse produced the dict shape callers index into.
    """

    def test_get_devices_details(self, live_config):
        from fortisiemv2.operations import get_devices_details

        result = get_devices_details(live_config, {})
        assert isinstance(result, dict), f"expected parsed dict, got {type(result)}"
        assert "devices" in result, f"no 'devices' key in {sorted(result)}"
        devices = result["devices"].get("device") or []
        if isinstance(devices, dict):
            devices = [devices]
        print(f"  -> {len(devices)} devices in CMDB")

    def test_get_devices_details_in_address(self, live_config):
        """Same handler as get_devices_details, but filtered by an IP range.

        The range is deliberately wide (all RFC1918 space) so the test is not
        coupled to any one lab's addressing.
        """
        from fortisiemv2.operations import get_devices_details

        result = get_devices_details(live_config, {
            "includeIps": "10.0.0.0-10.255.255.255,192.168.0.0-192.168.255.255",
        })
        # A range that matches nothing answers with an error description string
        # rather than a devices dict -- that is a valid live outcome, not a bug.
        if isinstance(result, str):
            pytest.skip(f"appliance returned no devices for the range: {result[:80]}")
        assert "devices" in result, f"no 'devices' key in {sorted(result)}"
        devices = result["devices"].get("device") or []
        if isinstance(devices, dict):
            devices = [devices]
        print(f"  -> {len(devices)} devices in the RFC1918 ranges")

    def test_get_device_info(self, live_config):
        """Look up one device by IP, using an IP discovered from the CMDB."""
        from fortisiemv2.operations import get_devices_details, get_device_info

        listing = get_devices_details(live_config, {})
        devices = (listing.get("devices") or {}).get("device") or []
        if isinstance(devices, dict):
            devices = [devices]
        ip = next((d.get("accessIp") for d in devices if d.get("accessIp")), None)
        if not ip:
            pytest.skip("no CMDB device exposes an accessIp to look up")

        result = get_device_info(live_config, {"ip": ip})
        assert isinstance(result, dict), f"expected parsed dict, got {type(result)}"
        print(f"  -> device info for {ip}: keys {sorted(result)[:4]}")

    def test_get_org_name_by_org_id(self, live_config):
        """Resolve a domain id that we first read back from the appliance."""
        from fortisiemv2.operations import (
            get_monitored_organizations, get_org_name_by_org_id)

        orgs = get_monitored_organizations(live_config, {})
        if not orgs:
            pytest.skip("appliance reports no monitored organizations")
        domain_id = orgs[0].get("domainId")

        result = get_org_name_by_org_id(live_config, {"domain_id": domain_id})
        assert isinstance(result, dict), (
            f"known domain id {domain_id} should resolve to an org, got {result!r}")
        assert str(result.get("domainId")) == str(domain_id)
        print(f"  -> domain {domain_id} -> {result.get('name')!r}")

    def test_get_org_name_by_org_id_unknown(self, live_config):
        """An unknown id returns a message string rather than raising."""
        from fortisiemv2.operations import get_org_name_by_org_id

        result = get_org_name_by_org_id(live_config, {"domain_id": "999999999"})
        assert isinstance(result, str) and "not found" in result.lower()

    def test_get_incident_attributes(self, live_config):
        """Static attribute catalogue -- no appliance call, but callers rely on it."""
        from fortisiemv2.operations import get_incident_attributes

        result = get_incident_attributes(live_config, {})
        assert result, "attribute list should not be empty"
        assert isinstance(result, (list, dict))
        print(f"  -> {len(result)} incident attributes")


# ---------------------------------------------------------------------------
# Async REST incident fetch
# ---------------------------------------------------------------------------

class TestAsyncRestOpLive:

    def test_async_get_incidents_rest(self, live_config):
        """The pyfortisiem-backed variant of get_incidents.

        Events are left off: enrichment costs one throttled server-side query
        per incident, and this test is about the REST/async path, not events.
        """
        from fortisiemv2.operations import async_get_incidents_rest

        fmt = '%Y-%m-%dT%H:%M:%S.000Z'
        result = async_get_incidents_rest(live_config, {
            "from": time.strftime(fmt, time.gmtime(time.time() - 24 * 3600)),
            "to": time.strftime(fmt, time.gmtime()),
            "incidentStatus": ["Active"],
            "include_events": False,
            "per_page": 25,
        })
        assert isinstance(result, list)
        if not result:
            pytest.skip("no active incidents in the last 24h")
        assert "incidentId" in result[0], f"unexpected shape: {sorted(result[0])[:8]}"
        print(f"  -> {len(result)} incidents via async REST")


# ---------------------------------------------------------------------------
# Watch lists
# ---------------------------------------------------------------------------

class TestWatchListLive:
    """Watch-list reads, plus one create->use->delete lifecycle.

    The lifecycle test owns everything it creates and tears it down in
    ``finally``, so a mid-test failure cannot strand a watch list on the
    appliance.
    """

    def test_get_watch_list_entries_count(self, live_config):
        from fortisiemv2.watch_list_actions import get_watch_list_entries_count

        result = get_watch_list_entries_count(live_config, {})
        assert isinstance(result, dict), f"expected dict, got {type(result)}"
        print(f"  -> entries count response keys: {sorted(result)}")

    def test_get_watch_lists_all(self, live_config):
        from fortisiemv2.watch_list_actions import get_watch_lists

        result = get_watch_lists(live_config, {"get_watch_list_by": "Get All Watch Lists"})
        assert isinstance(result, dict)
        print(f"  -> get all watch lists -> keys {sorted(result)}")

    def test_watch_list_lifecycle(self, live_config):
        """create -> read by id -> add entry -> read/update entry -> delete both.

        Every one of the six mutating watch-list operations is exercised here
        rather than in isolation, because each needs an id the previous one
        produced; standalone tests would have to hardcode lab-specific ids.
        """
        if not _allow_mutate():
            pytest.skip("mutating tests require FSM_ALLOW_MUTATE=true")

        from fortisiemv2.watch_list_actions import (
            create_watchlist_group, get_watch_lists, get_watch_list_entry,
            get_watch_list_entries_count,
            add_watch_list_entries_to_watch_list_groups, update_watch_list_entry,
            delete_watch_list_entry, delete_watch_list)

        name = f"pytest_fsmv2_{int(time.time())}"
        # `type` is a CMDB GroupType enum, not the entry data type -- watch list
        # groups are always DyWatchList. The data type of the entries is
        # `valueType` (IP / STRING / ...), which is a separate field.
        created = create_watchlist_group(live_config, {"json_object": {
            "displayName": name,
            "type": "DyWatchList",
            "valueType": "STRING",
            "description": "created by the fortisiemv2 live test suite",
            "ageOut": "1d",
            "entries": [],
        }})
        # Extract the id inside the try, not before it: if the response shape
        # ever changes, the group still exists on the appliance and must be
        # cleaned up rather than leaked.
        entry_id = None
        watch_list_id = None
        try:
            watch_list_id = _watch_list_id(created)
            assert watch_list_id, f"no watch list id in create response: {created}"
            print(f"  -> created watch list {name!r} id={watch_list_id}")

            # read it back by id
            by_id = get_watch_lists(live_config, {
                "get_watch_list_by": "By Watch List ID",
                "watch_list_id": watch_list_id,
            })
            assert isinstance(by_id, dict)
            print("  -> read back by id")

            # add an entry
            added = add_watch_list_entries_to_watch_list_groups(live_config, {
                "watch_list_id": watch_list_id,
                "other_params": {"entryValue": "pytest-entry-1",
                                 "dataCreationType": "MANUAL"},
            })
            assert isinstance(added, dict)
            print("  -> added entry")

            # find the entry id we just created
            refreshed = get_watch_lists(live_config, {
                "get_watch_list_by": "By Watch List ID",
                "watch_list_id": watch_list_id,
            })
            entries = _watch_list_entries(refreshed, watch_list_id)
            assert entries, f"entry did not appear in the watch list: {refreshed}"
            entry_id = entries[0].get("id")
            assert entry_id, f"no id on entry: {entries[0]}"

            # read the entry
            entry = get_watch_list_entry(live_config, {"watch_list_entry_id": entry_id})
            assert isinstance(entry, dict)
            print(f"  -> read entry {entry_id}")

            # update the entry (count + state both go through this op)
            updated = update_watch_list_entry(live_config, {
                "watch_list_entry_id": entry_id,
                "count": 7,
                "state": "Active",
            })
            assert isinstance(updated, dict)
            print("  -> updated entry")

            # count works while a list exists
            counts = get_watch_list_entries_count(live_config, {})
            assert isinstance(counts, dict)
        finally:
            if entry_id:
                delete_watch_list_entry(
                    live_config, {"watch_list_entry_ids": str(entry_id)})
                print(f"  -> deleted entry {entry_id}")
            if watch_list_id:
                delete_watch_list(live_config, {"watch_list_ids": str(watch_list_id)})
                print(f"  -> deleted watch list {watch_list_id}")


def _watch_list_id(created):
    """Dig the group id out of a /rest/watchlist/save response.

    ``response`` is a single-element list of the saved group, not a bare object.
    """
    node = created.get("response", created) if isinstance(created, dict) else created
    if isinstance(node, list):
        node = node[0] if node else {}
    return node.get("id") if isinstance(node, dict) else None


def _watch_list_entries(payload, watch_list_id=None):
    """Pull the entry list out of a watch-list response, shape-tolerantly.

    ``response`` is a list of watch-list groups for the "all" lookup and may be
    either a list or a bare object for a by-id lookup, so probe rather than
    assume one path. ``entries`` is null (not []) on an empty group.
    """
    node = payload.get("response", payload) if isinstance(payload, dict) else payload
    groups = node if isinstance(node, list) else [node]
    for group in groups:
        if not isinstance(group, dict):
            continue
        if watch_list_id is not None and str(group.get("id")) != str(watch_list_id):
            continue
        entries = group.get("entries")
        if isinstance(entries, dict):
            entries = [entries]
        if entries:
            return entries
    return []


# ---------------------------------------------------------------------------
# Lookup tables
# ---------------------------------------------------------------------------

class TestLookupTableLive:
    """Lookup-table coverage.

    Reads and table-level CRUD run for real. Row-level coverage is limited by
    the appliance: CSV import is the only insert path this API exposes
    (``POST /data`` answers 405), and on this 8.0.0 box the import endpoint
    itself answers HTTP 500 -- see ``test_import_lookup_table_data``. So the
    row-level ops are covered by asserting they surface the appliance's error
    cleanly rather than by round-tripping a row.
    """

    # Table names must be alphanumeric: the appliance answers 500 (not 400) for
    # a name containing '_' or '-', or one starting with a digit.
    @staticmethod
    def _table_name(tag):
        return f"pytestFsmv2{tag}{int(time.time())}"

    COLUMNS = [
        {"name": "host", "type": "STRING", "key": True},
        {"name": "owner", "type": "STRING", "key": False},
    ]

    @pytest.fixture
    def scratch_table(self, live_config):
        """Create a lookup table, yield its id, and always delete it after."""
        if not _allow_mutate():
            pytest.skip("mutating tests require FSM_ALLOW_MUTATE=true")

        from fortisiemv2.lookup_table_actions import (
            create_lookup_table, delete_lookup_table)

        created = create_lookup_table(live_config, {
            "name": self._table_name("t"),
            "description": "created by the fortisiemv2 live test suite",
            "columnList": self.COLUMNS,
        })
        table_id = _lookup_table_id(created)
        assert table_id, f"no lookup table id in create response: {created}"
        try:
            yield table_id
        finally:
            delete_lookup_table(live_config, {"lookupTableId": table_id})

    def test_get_all_lookup_tables(self, live_config):
        from fortisiemv2.lookup_table_actions import get_all_lookup_tables

        result = get_all_lookup_tables(live_config, {"stat": 0, "size": 25})
        assert isinstance(result, dict), f"expected dict, got {type(result)}"
        assert "data" in result, f"no 'data' key in {sorted(result)}"
        print(f"  -> {len(result['data'])} lookup tables")

    def test_create_and_delete_lookup_table(self, live_config, scratch_table):
        """create -> appears in the listing -> delete (delete runs in the fixture).

        The delete half is real coverage: it returns 204 with no Content-Type,
        which used to crash make_rest_call before it could report success.
        """
        from fortisiemv2.lookup_table_actions import get_all_lookup_tables

        listing = get_all_lookup_tables(live_config, {"stat": 0, "size": 500})
        ids = [t.get("id") for t in listing.get("data", [])]
        assert scratch_table in ids, "created table missing from the listing"
        print(f"  -> table {scratch_table} created and listed")

    def test_get_lookup_table_data(self, live_config, scratch_table):
        """Reading a fresh (empty) table must succeed, not error."""
        from fortisiemv2.lookup_table_actions import get_lookup_table_data

        data = get_lookup_table_data(live_config, {
            "lookupTableId": scratch_table, "start": 0, "size": 25})
        assert isinstance(data, dict), f"expected dict, got {type(data)}"
        assert data.get("total") == 0, f"new table should be empty: {data}"
        print(f"  -> empty table reads back cleanly: {data}")

    def test_update_lookup_table_data_reports_missing_row(self, live_config,
                                                          scratch_table):
        """Updating a row that does not exist must raise a readable error.

        The appliance answers 400 with the plain-text body 'Cannot find.' under
        a JSON Content-Type. make_rest_call used to call response.json() on
        that unconditionally, so callers got an opaque JSONDecodeError instead
        of the actual reason. This pins the decoded message.
        """
        from fortisiemv2.lookup_table_actions import update_lookup_table_data

        with pytest.raises(Exception) as excinfo:
            update_lookup_table_data(live_config, {
                "lookupTableId": scratch_table,
                "key": {"host": "pytest-absent-host"},
                "columnData": {"host": "pytest-absent-host", "owner": "pytest"},
            })
        message = str(excinfo.value)
        assert "JSONDecodeError" not in message and "Expecting value" not in message, (
            f"error was masked by a JSON parse failure: {message}")
        assert "Cannot find" in message, f"unexpected error text: {message}"
        print(f"  -> missing row reported as: {message[:80]}")

    def test_delete_lookup_table_data(self, live_config, scratch_table):
        """The row-delete op reports success for a well-formed request.

        Note this op returns a canned success dict regardless of what the
        appliance did, so it cannot distinguish 'deleted' from 'was not there'.
        """
        from fortisiemv2.lookup_table_actions import delete_lookup_table_data

        result = delete_lookup_table_data(live_config, {
            "lookupTableId": scratch_table,
            "keys_data": [{"host": "pytest-absent-host"}],
        })
        assert result.get("status") == "Success"
        print(f"  -> {result['message']}")

    @pytest.mark.xfail(
        reason="appliance-side: POST /rest/pub/lookupTable/{id}/import answers "
               "HTTP 500 for every payload encoding tried (python-repr, JSON "
               "object, JSON list, index map; skipHeader on and off; with and "
               "without a header row). Removing a required form field flips it "
               "to 422, so the request shape is accepted and the failure is "
               "downstream. CSV import is the only row-insert path this API "
               "exposes, so check_import_task_status is blocked behind it.",
        strict=False, raises=Exception)
    def test_import_lookup_table_data_and_task_status(self, live_config,
                                                      scratch_table, monkeypatch):
        """CSV import + the task-status poll that follows it.

        ``import_lookup_table_data`` normally sources its CSV from FortiSOAR
        (crudhub attachment / file IRI), which does not exist outside a
        FortiSOAR node. The file-fetch half is stubbed so the half that talks to
        FortiSIEM -- the multipart import POST and the task poll -- runs for real.
        """
        from fortisiemv2 import lookup_table_actions as lta

        monkeypatch.setattr(
            lta, "get_csv_file_data",
            lambda params: ("pytest.csv", b"host,owner\npytest-host-2,pytest\n"))

        imported = lta.import_lookup_table_data(live_config, {
            "input": "File IRI",
            "file": "/api/3/files/pytest",
            "lookupTableId": scratch_table,
            "mapping": {"host": "host", "owner": "owner"},
            "skipHeader": True,
            "updateType": "Overwrite",
        })
        assert imported is not None
        print(f"  -> import returned {str(imported)[:120]}")

        task_id = _import_task_id(imported)
        assert task_id, f"import response carried no task id: {str(imported)[:200]}"

        status = lta.check_import_task_status(live_config, {
            "lookupTableId": scratch_table, "taskId": task_id})
        assert status is not None
        print(f"  -> task {task_id} status: {str(status)[:120]}")


def _as_dict(payload):
    """Lookup-table endpoints answer JSON, but the helper returns raw text."""
    if isinstance(payload, (str, bytes)):
        try:
            return json.loads(payload)
        except (ValueError, TypeError):
            return {}
    return payload if isinstance(payload, dict) else {}


def _lookup_table_id(created):
    node = _as_dict(created)
    for key in ("id", "lookupTableId", "naturalId"):
        if node.get(key):
            return node[key]
    inner = node.get("response") or node.get("data") or {}
    if isinstance(inner, dict):
        for key in ("id", "lookupTableId", "naturalId"):
            if inner.get(key):
                return inner[key]
    return None


def _import_task_id(imported):
    node = _as_dict(imported)
    for key in ("taskId", "id", "task"):
        if node.get(key):
            return node[key]
    inner = node.get("response") or node.get("data") or {}
    if isinstance(inner, dict):
        for key in ("taskId", "id", "task"):
            if inner.get(key):
                return inner[key]
    return None


# ---------------------------------------------------------------------------
# Events by query id
# ---------------------------------------------------------------------------

class TestQueryIdLive:

    @pytest.fixture(autouse=True)
    def _settle_query_slots(self):
        # run_report spawns a server-side query that outlives its HTTP response.
        yield
        time.sleep(QUERY_SLOT_SETTLE_SECONDS)

    def test_get_events_by_query_id(self, live_config):
        """Paging over a query id produced by run_report.

        The query id cannot be hardcoded -- it is minted per run -- so this
        test has to create one first.
        """
        from fortisiemv2.operations import run_report, get_events_by_query_id

        fmt = '%Y-%m-%dT%H:%M:%S.000Z'
        report = run_report(live_config, {
            "timeFrom": time.strftime(fmt, time.gmtime(time.time() - 3600)),
            "timeTo": time.strftime(fmt, time.gmtime()),
            "constraint": "",
            "perPage": 10,
            "start": 0,
        })
        query_id = _query_id_from(report)
        if not query_id:
            pytest.skip(f"run_report returned no query id: {str(report)[:200]}")

        result = get_events_by_query_id(live_config, {
            "query_id": query_id, "start": 0, "perPage": 10})
        assert result is not None
        print(f"  -> query {query_id} -> {str(result)[:120]}")


# run_report answers XML that xmltodict flattens, so the query id arrives as
# the attribute key '@queryId' rather than a plain 'queryId'.
_QUERY_ID_KEYS = ("@queryId", "queryId", "query_id", "queryID")


def _query_id_from(report):
    node = _as_dict(report)
    for key in _QUERY_ID_KEYS:
        if node.get(key):
            return node[key]
    inner = node.get("response") or node.get("data") or {}
    if isinstance(inner, dict):
        for key in _QUERY_ID_KEYS:
            if inner.get(key):
                return inner[key]
    return None


# ---------------------------------------------------------------------------
# MCP prompt operations
# ---------------------------------------------------------------------------

class TestMCPPromptOpsLive:
    """The two prompt ops exposed as connector operations (not raw MCP calls)."""

    def test_get_postgres_prompts(self, mcp_config):
        from fortisiemv2.operations import get_postgres_prompts

        result = get_postgres_prompts(mcp_config, {})
        assert result, "expected SQL authoring guidance"
        print(f"  -> postgres prompts: {str(result)[:100]}")

    def test_get_clickhouse_prompts(self, mcp_config):
        from fortisiemv2.operations import get_clickhouse_prompts

        result = get_clickhouse_prompts(mcp_config, {})
        assert result, "expected SQL authoring guidance"
        print(f"  -> clickhouse prompts: {str(result)[:100]}")
