"""
Copyright start
Copyright (C) 2008 - 2024 FortinetInc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end
"""

import asyncio
import logging
import time

logger = logging.getLogger('fortinet-fortisiemv2')

from .constants import PARAMS_MAPPING, INCIDENT_CATEGORY_MAPPING
from .connections import get_async_client, run_async
from .field_mapping import map_incident_to_alert, map_incidents_batch
from .utils import parse_datetime_to_epoch

# FortiSIEM will not return more than this many rows from a single
# /pub/incident call, whatever `size` asks for (verified against a live
# appliance: size=5000 yields 1000).
MAX_PAGE_SIZE = 1000

# Safety ceiling on one ingestion run, so a wide backfill window cannot pull an
# unbounded result set into memory and stall the playbook.
MAX_INCIDENTS_PER_RUN = 5000

# Parallel triggering-event lookups.
#
# FortiSIEM rejects the 11th concurrent *server-side query* per source IP with a
# 429, and a triggering-events query stays alive after its HTTP response
# returns -- so the effective ceiling is well under 10. The client retries 429
# but only ~3s in total with no jitter, which is not long enough for the query
# slots to drain, so exceeding this just converts incidents into empty evidence.
#
# Measured against a live appliance over the same window: 8 -> 11 dropped
# enrichments in 20.1s; 4 -> zero drops in 19.7s; 2 -> zero drops but 31.0s.
# 4 is the knee -- going wider buys nothing because the time is spent failing.
EVENT_ENRICHMENT_CONCURRENCY = 4


def _status_to_codes(status_list):
    """Convert human-readable status names to FortiSIEM numeric status codes."""
    if not status_list:
        return [0]
    codes = []
    for s in status_list:
        code = PARAMS_MAPPING.get(s)
        if code is not None:
            codes.append(int(code))
    return codes or [0]


def _category_to_codes(category_list):
    """Convert human-readable category names to FortiSIEM numeric category codes."""
    if not category_list:
        return None
    codes = []
    for c in category_list:
        code = INCIDENT_CATEGORY_MAPPING.get(c)
        if code is not None:
            codes.append(code)
    return codes or None


def ingest_incidents(config, params):
    """Native ingestion operation -- fetches incidents from FortiSIEM and maps
    them to FortiSOAR alert-compatible dicts.

    Uses ``AsyncFortiSIEMClient`` for fast, typed, concurrent fetching.
    Optionally enriches each incident with triggering events.

    Params:
        from (str):            Start datetime (ISO format, e.g. '2024-01-01T00:00:00.000Z')
        to (str):              End datetime
        incidentStatus (list): Human-readable status names (['Active', 'Manually Cleared', ...])
        incidentCategory (list): Human-readable category names (['Security', 'Availability', ...])
        severity (list):      Severity categories (['High', 'Medium', 'Low'])
        include_events (bool): Whether to enrich with triggering events
        event_count (int):    Number of events per incident
        size (int):           Page size for incident query
        use_query_lifecycle (bool): Use the async query lifecycle for large event sets
        include_iocs (bool):  Fetch IOCs for each incident (requires MCP)

    Returns:
        list[dict]: Mapped alert dicts ready for FortiSOAR ingestion.
    """
    time_from = _parse_time_ms(params.get("from"))
    time_to = _parse_time_ms(params.get("to"))

    if not time_from or not time_to:
        now_ms = int(time.time() * 1000)
        if not time_to:
            time_to = now_ms
        if not time_from:
            time_from = now_ms - (24 * 60 * 60 * 1000)

    status_codes = _status_to_codes(params.get("incidentStatus"))
    category_codes = _category_to_codes(params.get("incidentCategory"))
    include_events = params.get("include_events", True)
    event_count = params.get("event_count", 5)
    size = params.get("size", 100)
    use_query_lifecycle = params.get("use_query_lifecycle", False)

    extra_filters = {}
    if category_codes:
        extra_filters["phIncidentCategory"] = category_codes
    severity = params.get("severity")
    if severity:
        extra_filters["eventSeverityCat"] = severity
    event_type = params.get("eventType")
    if event_type:
        if isinstance(event_type, str):
            extra_filters["eventType"] = [event_type]
        elif isinstance(event_type, list):
            extra_filters["eventType"] = event_type

    return run_async(_ingest_incidents_async(
        config, time_from, time_to, status_codes, extra_filters,
        include_events, event_count, size, use_query_lifecycle,
    ))


async def _list_all_incidents(fsm, time_from, time_to, status_codes,
                              extra_filters, size):
    """Page through ``/pub/incident`` until the window is exhausted.

    ``list_incidents`` is a single request capped at ``size``, and FortiSIEM
    itself refuses to return more than ``MAX_PAGE_SIZE`` per call. Without
    paging, any window holding more incidents than the cap is silently
    truncated -- and because the ingestion playbook advances its last-pull-time
    watermark regardless, the surplus is never fetched again. The default sort
    is descending by ``incidentLastSeen``, so the records dropped are the
    *oldest* ones: exactly those adjacent to the watermark being moved past.
    """
    page_size = min(int(size or MAX_PAGE_SIZE), MAX_PAGE_SIZE)
    collected = []
    seen = set()
    start = 0
    while True:
        page = await fsm.list_incidents(
            time_from=time_from, time_to=time_to,
            status=status_codes, size=page_size, start=start,
            # Page on an immutable, monotonic key. The library default
            # (incidentLastSeen, descending) reshuffles between requests as
            # incidents recur, which both duplicates and *skips* rows -- paging
            # a live window that way was measured losing records outright,
            # while incidentId ascending returned a clean set.
            order_by="incidentId", descending=False,
            extra_filters=extra_filters or None,
        )
        # Defensive: ordering is stable, but never let a server-side quirk put
        # the same incident through the mapper twice.
        added = 0
        for inc in page:
            if inc.incident_id not in seen:
                seen.add(inc.incident_id)
                collected.append(inc)
                added += 1
        # A short page means the window is exhausted. `added == 0` catches a
        # server that ignores `start` and replays page one forever -- without
        # it, dedupe would keep `collected` flat and the ceiling check below
        # could never fire.
        if len(page) < page_size or added == 0:
            break
        if len(collected) >= MAX_INCIDENTS_PER_RUN:
            break
        start += page_size

    if len(collected) >= MAX_INCIDENTS_PER_RUN:
        # Loud, because this IS lossy: the ingestion playbook advances its
        # watermark to the end of the window regardless, so whatever is
        # discarded here will not be picked up on a later run. Reaching this
        # ceiling means the window or the filters are too wide.
        logger.error(
            "Truncated at the %d-incident ceiling for window %s-%s; incidents "
            "beyond it are NOT ingested and will not be retried. Narrow the "
            "ingestion window or tighten the status/severity filters.",
            MAX_INCIDENTS_PER_RUN, time_from, time_to,
        )
    return collected[:MAX_INCIDENTS_PER_RUN]


async def _ingest_incidents_async(
    config, time_from, time_to, status_codes, extra_filters,
    include_events, event_count, size, use_query_lifecycle,
):
    """Async implementation of ingest_incidents."""
    async with get_async_client(config) as fsm:
        incidents = await _list_all_incidents(
            fsm, time_from, time_to, status_codes, extra_filters, size,
        )
        if include_events:
            fetch_events = (
                fsm.get_associated_events_via_query
                if use_query_lifecycle
                else fsm.get_associated_events
            )
            failures = []

            async def _enrich(inc):
                try:
                    events = await fetch_events(
                        inc.incident_id, size=event_count,
                        time_from=time_from, time_to=time_to,
                    )
                    return {**inc.model_dump(by_alias=True, exclude_none=False),
                            "events": [e.model_dump(by_alias=True, exclude_none=False) for e in events]}
                except Exception as exc:
                    # The incident still gets ingested, but without its events.
                    # Record it: an enrichment failure is indistinguishable
                    # downstream from an incident that genuinely has no events.
                    failures.append(inc.incident_id)
                    logger.warning("Event enrichment failed for incident %s: %s", inc.incident_id, exc)
                    return {**inc.model_dump(by_alias=True, exclude_none=False), "events": []}

            # Enrich with bounded concurrency -- see EVENT_ENRICHMENT_CONCURRENCY.
            # Unbounded would 429; strictly sequential is one round-trip per
            # incident, which does not survive paging a wide window.
            sem = asyncio.Semaphore(EVENT_ENRICHMENT_CONCURRENCY)

            async def _enrich_bounded(inc):
                async with sem:
                    return await _enrich(inc)

            raw_incidents = list(await asyncio.gather(
                *(_enrich_bounded(inc) for inc in incidents)
            ))

            if failures:
                logger.error(
                    "Event enrichment failed for %d of %d incidents; they are "
                    "ingested with empty evidence. Incident IDs: %s",
                    len(failures), len(incidents), failures[:20],
                )
        else:
            raw_incidents = [_incident_to_dict(inc) for inc in incidents]

    logger.info("Ingested %d FortiSIEM incidents", len(raw_incidents))
    return map_incidents_batch(raw_incidents)


def _incident_to_dict(incident):
    """Convert a pydantic Incident to a plain dict (by_alias, all fields)."""
    if hasattr(incident, "model_dump"):
        return incident.model_dump(by_alias=True, exclude_none=False)
    if isinstance(incident, dict):
        return incident
    return dict(incident)


def _incident_with_events_to_dict(iwe):
    """Convert an IncidentWithEvents to a plain dict with events list."""
    if hasattr(iwe, "model_dump"):
        d = iwe.model_dump(by_alias=True, exclude_none=False)
        if "events" in d and d["events"]:
            d["events"] = [
                ev.model_dump(by_alias=True, exclude_none=False) if hasattr(ev, "model_dump") else ev
                for ev in d["events"]
            ]
        return d
    if isinstance(iwe, dict):
        return iwe
    return dict(iwe)


def _parse_time_ms(dt_str):
    """Parse a datetime string to epoch milliseconds, or None."""
    if not dt_str:
        return None
    epoch = parse_datetime_to_epoch(dt_str)
    if epoch is not None:
        return epoch * 1000
    try:
        return int(float(dt_str))
    except (ValueError, TypeError):
        return None
