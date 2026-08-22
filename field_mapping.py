"""
Copyright start
Copyright (C) 2008 - 2024 FortinetInc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end
"""

import json
import logging
import re

logger = logging.getLogger('fortinet-fortisiemv2')

INCIDENT_STATUS_MAP = {
    0: "Open",
    1: "Resolved",
    2: "Closed",
    3: "Resolved",
}

INCIDENT_CATEGORY_MAP = {
    1: "Availability",
    2: "Performance",
    3: "Change",
    4: "Security",
    5: "Other",
}

SEVERITY_MAP = {
    "MINIMAL": "Minimal",
    "LOW": "Low",
    "MEDIUM": "Medium",
    "HIGH": "High",
    "CRITICAL": "Critical",
}

# Fallback when ``eventSeverityCat`` is absent: FortiSIEM's numeric
# ``eventSeverity`` runs 0-10.  Buckets chosen to line up with the five
# FortiSOAR Severity picklist values.
SEVERITY_NUMERIC_BUCKETS = (
    (2, "Minimal"),
    (5, "Low"),
    (7, "Medium"),
    (9, "High"),
)


def resolve_severity(severity_cat, severity_num=None):
    """Resolve a FortiSIEM severity to a FortiSOAR ``Severity`` picklist value.

    Always returns one of the five picklist values, never a passthrough of the
    raw FortiSIEM string -- an unmapped value makes the ingestion playbook's
    ``resolveRange`` miss and the alert POST fail with a picklist 400.
    """
    if severity_cat:
        mapped = SEVERITY_MAP.get(str(severity_cat).strip().upper())
        if mapped:
            return mapped
    try:
        num = int(severity_num)
    except (TypeError, ValueError):
        return "Low"
    for ceiling, label in SEVERITY_NUMERIC_BUCKETS:
        if num <= ceiling:
            return label
    return "Critical"

# Every value here MUST be a member of the FortiSOAR ``AlertType`` picklist.
# The ingestion playbook resolves this through ``resolveRange``, and a value
# the picklist does not contain fails the alert POST with a 400 -- the same
# trap ``resolve_severity`` guards against.  Live-verified on 8.0.0: the
# previous table emitted "Security", "Availability", "Change" and
# "Anomaly Detection", none of which are picklist members.
VALID_ALERT_TYPES = {
    "Actionable Threat Feeds", "Beaconing", "Brute Force Attempts",
    "Command and Control", "Compliance", "Concurrent Login",
    "Data Exfiltration", "Data Leakage", "Denial of Service",
    "Domain User Created", "Firewall Configuration Change",
    "Improper Disposal", "Lateral Movement", "Lost / Stolen",
    "MITRE ATT&CK", "Malware", "Other / Unknown", "Password Reset",
    "Phishing", "Policy Violation", "Ransomware", "Reconnaissance",
    "S3 Policy Change", "Scheduled Task Created", "Sunburst",
    "Suspicious Email", "Unstructured Feeds", "User Group Changed",
    "Vulnerable Asset",
}

DEFAULT_ALERT_TYPE = "Other / Unknown"

# FortiSIEM's ``phSubIncidentCategory`` carries a MITRE tactic name for
# Security incidents.  Only tactics with an unambiguous picklist counterpart
# are listed; everything else falls through to the MITRE ATT&CK / default
# handling in ``_resolve_incident_type``.
TACTIC_TYPE_MAP = {
    "command and control": "Command and Control",
    "lateral movement": "Lateral Movement",
    "reconnaissance": "Reconnaissance",
    "discovery": "Reconnaissance",
    "exfiltration": "Data Exfiltration",
    "credential access": "Brute Force Attempts",
    "initial access": "Phishing",
    "resource development": "Actionable Threat Feeds",
}

# Non-MITRE sub-categories that still have a clean picklist counterpart.
SUBCATEGORY_TYPE_MAP = {
    "malware": "Malware",
    "malware activity": "Malware",
    "ransomware": "Ransomware",
    "data exfiltration": "Data Exfiltration",
    "brute force": "Brute Force Attempts",
    "network scan": "Reconnaissance",
    "denial of service": "Denial of Service",
    "phishing": "Phishing",
    "policy violation": "Policy Violation",
    "unauthorized access": "Concurrent Login",
}

# Category-level fallbacks for the non-Security categories.
CATEGORY_TYPE_MAP = {
    "Change": "Policy Violation",
    "Availability": "Other / Unknown",
    "Performance": "Other / Unknown",
    "Other": "Other / Unknown",
}


def parse_attrib_pairs(attrib_str):
    """Parse FortiSIEM's 'key:value,key:value' format into a flat dict.

    FortiSIEM encodes source and target as comma-separated key:value pairs,
    e.g. ``"srcIpAddr:10.0.0.1, computer:server01"``.  This function splits
    them into a dict with the keys as-is (matching the FortiSIEM wire names).
    """
    if not attrib_str or not isinstance(attrib_str, str):
        return {}
    result = {}
    for pair in attrib_str.split(","):
        if ":" not in pair:
            continue
        idx = pair.index(":")
        key = pair[:idx].strip()
        val = pair[idx + 1:].strip()
        if key:
            result[key] = val
    return result


def parse_mitre(attack_technique_raw):
    """Parse FortiSIEM's ``attackTechnique`` field into structured MITRE fields.

    The raw value is a JSON string containing a list of objects with
    ``techniqueid`` and ``name`` keys, e.g.::

        '[{"name": "Remote Services", "techniqueid": "T1021"}]'

    Returns a dict with ``mitre_tactic_id``, ``mitre_technique_id``,
    ``mitre_technique_name``, and ``mitre_techniques`` (list of all
    technique dicts).
    """
    if not attack_technique_raw or not isinstance(attack_technique_raw, str):
        return {}
    try:
        techniques = json.loads(attack_technique_raw)
    except (ValueError, TypeError):
        return {}
    if not isinstance(techniques, list):
        techniques = [techniques] if isinstance(techniques, dict) else []

    technique_ids = []
    technique_names = []
    for t in techniques:
        if isinstance(t, dict):
            tid = t.get("techniqueid") or t.get("techniqueId") or t.get("id")
            tname = t.get("name") or t.get("techniqueName")
            if tid:
                technique_ids.append(tid)
            if tname:
                technique_names.append(tname)

    return {
        "mitre_tactic_id": technique_ids[0] if technique_ids else None,
        "mitre_technique_id": technique_ids[0] if technique_ids else None,
        "mitre_technique_name": technique_names[0] if technique_names else None,
        "mitre_technique_ids": technique_ids,
        "mitre_technique_names": technique_names,
        "mitre_techniques": techniques,
    }


def _resolve_category(category_raw):
    """Resolve phIncidentCategory (int or string) to a human label."""
    if category_raw is None:
        return None
    try:
        return INCIDENT_CATEGORY_MAP.get(int(category_raw))
    except (ValueError, TypeError):
        if isinstance(category_raw, str) and category_raw in INCIDENT_CATEGORY_MAP.values():
            return category_raw
        return str(category_raw) if category_raw else None


def _resolve_incident_type(category_label, sub_category, has_mitre=False):
    """Resolve category + sub-category to a FortiSOAR ``AlertType`` value.

    Guaranteed to return a member of ``VALID_ALERT_TYPES``.  A Security
    incident that carries ATT&CK data but no tactic-specific counterpart is
    typed ``MITRE ATT&CK``, which is both a real picklist value and more
    informative than the catch-all.
    """
    key = (sub_category or "").strip().lower()
    resolved = SUBCATEGORY_TYPE_MAP.get(key) or TACTIC_TYPE_MAP.get(key)
    if not resolved and category_label == "Security":
        resolved = "MITRE ATT&CK" if has_mitre else DEFAULT_ALERT_TYPE
    if not resolved:
        resolved = CATEGORY_TYPE_MAP.get(category_label, DEFAULT_ALERT_TYPE)
    return resolved if resolved in VALID_ALERT_TYPES else DEFAULT_ALERT_TYPE


# ---------------------------------------------------------------------------
# Human-readable description
# ---------------------------------------------------------------------------
#
# The alert `description` field is rendered as rich text by FortiSOAR, so it
# gets HTML rather than the raw `incidentDetail` payload.  Emitting that raw
# value was actively harmful: it is a JSON *string*, and the ingestion
# playbook's `{{ vars.item.description }}` hands it to FortiSOAR's templating,
# which parses the `{...}` and collapses the whole thing to the literal text
# "Array" -- live-verified on 8.0.0, where every ingested alert carried
# `description == "Array"`.
#
# For the same reason every value interpolated below has its braces replaced
# with HTML entities: Windows command lines routinely contain GUIDs in braces,
# which would re-trigger exactly that parse.  The entities render identically.

# Keys inside `incidentDetailJson` that carry no analyst value.
_DETAIL_SKIP = {"incidentCount"}

# Pretty labels for the detail keys FortiSIEM emits most often.
_DETAIL_LABELS = {
    "parentProcName": "Parent process",
    "procName": "Process",
    "command": "Command line",
    "targetUser": "Target user",
    "srcIpAddr": "Source IP",
    "destIpAddr": "Destination IP",
    "destIpPort": "Destination port",
    "hostName": "Host",
    "fileName": "File",
    "hashCode": "Hash",
}


def _esc(value):
    """HTML-escape a value and neutralise braces.

    Braces are escaped even though they are not HTML-special, because
    FortiSOAR's templating treats a `{...}` run in a rendered value as a
    literal to evaluate.  `&#123;` renders as `{` and survives that pass.
    """
    if value is None:
        return ""
    text = str(value)
    text = (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace('"', "&quot;"))
    return text.replace("{", "&#123;").replace("}", "&#125;")


def _label_for(key):
    """Human label for a detail key, falling back to a de-camel-cased form."""
    if key in _DETAIL_LABELS:
        return _DETAIL_LABELS[key]
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", str(key))
    return spaced[:1].upper() + spaced[1:]


def _detail_dict(raw):
    """Return `incidentDetail` as a dict, whether it arrives parsed or as JSON text."""
    parsed = raw.get("incidentDetailJson")
    if isinstance(parsed, dict) and parsed:
        return parsed
    detail = raw.get("incidentDetail")
    if isinstance(detail, dict):
        return detail
    if isinstance(detail, str) and detail.strip().startswith("{"):
        try:
            loaded = json.loads(detail)
        except (ValueError, TypeError):
            return {}
        if isinstance(loaded, dict):
            return loaded
    return {}


def _rows(pairs):
    """Render label/value pairs as table rows, dropping the empty ones."""
    out = []
    for label, value in pairs:
        if value in (None, "", [], {}):
            continue
        out.append(
            "<tr>"
            '<td style="padding:2px 12px 2px 0;vertical-align:top;'
            'white-space:nowrap"><b>{}</b></td>'
            '<td style="padding:2px 0;vertical-align:top">{}</td>'
            "</tr>".format(_esc(label), _esc(value))
        )
    return out


def build_description(raw, alert):
    """Build the rich-text alert description from a FortiSIEM incident.

    `raw` is the incident as FortiSIEM returned it; `alert` is the partially
    built alert dict, so the already-normalised values (severity, MITRE, parsed
    source/target) are reused instead of being re-derived.
    """
    parts = []

    headline = alert.get("rule_description") or alert.get("name") or "FortiSIEM incident"
    parts.append('<p style="margin:0 0 8px 0"><b>{}</b></p>'.format(_esc(headline)))

    overview = _rows([
        ("Incident", alert.get("external_id")),
        ("Category", " / ".join(x for x in (alert.get("category"),
                                            alert.get("subcategory")) if x)),
        ("Severity", alert.get("severity")),
        ("Status", alert.get("alert_state")),
        ("Reporting device", alert.get("reporting_device")),
        ("Reporting IP", alert.get("reporting_ip")),
        ("Source", _endpoint(alert.get("source_hostname"), alert.get("source_ip"),
                             None, alert.get("source_user"))),
        ("Target", _endpoint(alert.get("target_hostname") or alert.get("dest_hostname"),
                             alert.get("target_ip") or alert.get("dest_ip"),
                             alert.get("dest_port"), alert.get("target_user"))),
        ("First seen", alert.get("alert_generation_time")),
        ("Last seen", alert.get("last_observed_time")),
        ("Event count", alert.get("event_count")),
        ("Rule", alert.get("rule_name")),
    ])
    if overview:
        parts.append("<table>{}</table>".format("".join(overview)))

    techniques = alert.get("mitre_techniques") or []
    if techniques:
        items = []
        for t in techniques:
            if not isinstance(t, dict):
                continue
            tid = t.get("techniqueid") or t.get("techniqueId") or t.get("id")
            name = t.get("name") or t.get("techniqueName")
            items.append("<li>{}</li>".format(
                _esc(" - ".join(x for x in (tid, name) if x))))
        if items:
            parts.append('<p style="margin:8px 0 2px 0"><b>MITRE ATT&amp;CK</b></p>')
            parts.append("<ul>{}</ul>".format("".join(items)))

    detail_rows = _rows([
        (_label_for(k), v) for k, v in sorted(_detail_dict(raw).items())
        if k not in _DETAIL_SKIP and v not in (None, "", [], {})
    ])
    if detail_rows:
        parts.append('<p style="margin:8px 0 2px 0"><b>Incident detail</b></p>')
        parts.append("<table>{}</table>".format("".join(detail_rows)))

    evidence = alert.get("evidence") or []
    if evidence:
        parts.append(
            '<p style="margin:8px 0 0 0"><i>{} triggering event(s) captured in '
            "the alert's source data.</i></p>".format(len(evidence))
        )

    return "".join(parts)


def _endpoint(hostname, ip, port, user):
    """Render 'host (ip:port) as user', omitting whichever parts are absent."""
    location = hostname or ""
    if ip and ip != hostname:
        location = "{} ({})".format(location, ip) if location else str(ip)
    if port:
        location = "{}:{}".format(location, port) if location else str(port)
    if user:
        location = "{} as {}".format(location, user) if location else "user {}".format(user)
    return location or None


def map_incident_to_alert(incident):
    """Map a FortiSIEM incident dict (or pydantic model) to a FortiSOAR alert dict.

    Handles the full FortiSIEM incident shape:
    - ``incidentId``         → ``external_id``
    - ``incidentTitle``      → ``name``
    - ``incidentStatus``     → ``alert_state`` (via INCIDENT_STATUS_MAP)
    - ``eventSeverityCat``   → ``severity`` (via resolve_severity)
    - ``phIncidentCategory`` → ``category`` (via INCIDENT_CATEGORY_MAP)
    - ``phSubIncidentCategory`` → ``subcategory`` and ``alert_type``
    - ``incidentFirstSeen``  → ``alert_generation_time`` (epoch ms → iso)
    - ``incidentLastSeen``   → ``last_observed_time`` (epoch ms → iso)
    - ``incidentSrc``        → ``source_ip``, ``source_hostname``, ``source_user`` (parsed)
    - ``incidentTarget``     → ``dest_ip``, ``dest_hostname``, ``target_user`` (parsed)
    - ``attackTechnique``    → MITRE ATT&CK fields (via parse_mitre)
    - ``eventType``          → ``rule_name``
    - ``eventName``          → ``rule_description``
    - ``incidentRptDevName`` → ``reporting_device``
    - ``incidentRptIp``      → ``reporting_ip``
    - ``incidentDetail``    → rendered into the rich-text ``description``
    - ``count``              → ``event_count``
    - ``events``             → ``evidence`` (list of event dicts)
    """
    raw = incident
    if hasattr(incident, "model_dump"):
        raw = incident.model_dump(by_alias=True, exclude_none=False)
    elif not isinstance(incident, dict):
        raw = dict(incident)

    incident_id = raw.get("incidentId")
    title = raw.get("incidentTitle") or raw.get("incident_title") or ""
    status_code = raw.get("incidentStatus")
    severity_cat = raw.get("eventSeverityCat") or raw.get("severity_category")
    category_raw = raw.get("phIncidentCategory") or raw.get("incident_category")
    sub_category = raw.get("phSubIncidentCategory")
    first_seen = raw.get("incidentFirstSeen") or raw.get("first_seen")
    last_seen = raw.get("incidentLastSeen") or raw.get("last_seen")
    incident_src = raw.get("incidentSrc") or raw.get("incident_src")
    incident_target = raw.get("incidentTarget") or raw.get("incident_target")
    attack_technique = raw.get("attackTechnique")
    event_type = raw.get("eventType")
    event_name = raw.get("eventName")
    rpt_dev = raw.get("incidentRptDevName")
    rpt_ip = raw.get("incidentRptIp")
    count = raw.get("count")
    events = raw.get("events", [])

    category_label = _resolve_category(category_raw)

    src_parsed = parse_attrib_pairs(incident_src) if isinstance(incident_src, str) else (incident_src or {})
    target_parsed = parse_attrib_pairs(incident_target) if isinstance(incident_target, str) else (incident_target or {})

    mitre = parse_mitre(attack_technique)
    alert_type = _resolve_incident_type(
        category_label, sub_category, has_mitre=bool(mitre.get("mitre_technique_ids")))

    evidence = []
    if events and isinstance(events, list):
        for ev in events:
            if hasattr(ev, "model_dump"):
                evidence.append(ev.model_dump(by_alias=True, exclude_none=False))
            elif isinstance(ev, dict):
                evidence.append(ev)

    alert = {
        "external_id": str(incident_id) if incident_id is not None else None,
        "name": title,
        "alert_state": INCIDENT_STATUS_MAP.get(status_code, "Open"),
        "severity": resolve_severity(severity_cat, raw.get("eventSeverity")),
        "category": category_label,
        "subcategory": sub_category,
        "alert_type": alert_type,
        "alert_generation_time": _epoch_ms_to_iso(first_seen),
        "last_observed_time": _epoch_ms_to_iso(last_seen),
        # FortiSOAR's date columns are integer epoch *seconds*.  Emitting them
        # here keeps all date arithmetic in Python: the playbook can assign
        # them directly instead of routing an ISO string through a jinja date
        # filter, which is the sort of thing that fails silently and leaves
        # every alert timestamped at ingest time.
        "alert_generation_epoch": _epoch_ms_to_seconds(first_seen),
        "last_observed_epoch": _epoch_ms_to_seconds(last_seen),
        "source_ip": src_parsed.get("srcIpAddr") if isinstance(src_parsed, dict) else None,
        "source_hostname": src_parsed.get("computer") or src_parsed.get("hostName") if isinstance(src_parsed, dict) else None,
        "source_user": src_parsed.get("user") if isinstance(src_parsed, dict) else None,
        "dest_ip": target_parsed.get("destIpAddr") if isinstance(target_parsed, dict) else None,
        "dest_hostname": target_parsed.get("destName") or target_parsed.get("hostName") if isinstance(target_parsed, dict) else None,
        "dest_port": _safe_int(target_parsed.get("destIpPort")) if isinstance(target_parsed, dict) else None,
        "target_user": target_parsed.get("targetUser") or target_parsed.get("user") if isinstance(target_parsed, dict) else None,
        "target_hostname": target_parsed.get("hostName") or target_parsed.get("destName") if isinstance(target_parsed, dict) else None,
        "target_ip": target_parsed.get("hostIpAddr") or target_parsed.get("destIpAddr") if isinstance(target_parsed, dict) else None,
        "rule_name": event_type,
        "rule_description": event_name,
        "reporting_device": rpt_dev,
        "reporting_ip": rpt_ip,
        "event_count": count,
        "evidence": evidence,
        "raw_incident": raw,
    }

    alert.update(mitre)

    # Built last: it reads the normalised values above rather than re-deriving
    # them from the raw incident.
    alert["description"] = build_description(raw, alert)

    alert = {k: v for k, v in alert.items() if v is not None}

    # The payload the ingestion playbook stores as ``sourcedata``: everything
    # here except the rendered description, which is presentation built from
    # values already present and accounted for ~30% of every stored blob
    # (live-verified on 8.0.0: 78 KB of 263 KB across 30 alerts).
    #
    # Deliberately a dict, NOT a pre-serialised JSON string. The playbook
    # renders it with ``| toJSON``; passing an already-serialised string
    # through a bare ``{{ }}`` instead makes FortiSOAR parse the leading
    # ``{...}`` and collapse the whole value to the literal text "Array" --
    # the same trap ``build_description`` documents, hit a second time and
    # live-verified on 8.0.0.
    alert["source_payload"] = {k: v for k, v in alert.items() if k != "description"}

    return alert


def _epoch_ms_to_iso(epoch_ms):
    """Convert epoch milliseconds to ISO 8601 string, or None."""
    if not epoch_ms:
        return None
    try:
        from datetime import datetime, timezone
        dt = datetime.fromtimestamp(int(epoch_ms) / 1000, tz=timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    except (ValueError, TypeError, OSError):
        return None


def _epoch_ms_to_seconds(epoch_ms):
    """Convert epoch milliseconds to whole epoch seconds, or None."""
    if not epoch_ms:
        return None
    try:
        return int(epoch_ms) // 1000
    except (ValueError, TypeError):
        return None


def _safe_int(val):
    """Safely convert a value to int, or None."""
    if val is None or val == "":
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def map_incidents_batch(incidents):
    """Map a list of FortiSIEM incidents to FortiSOAR alert dicts."""
    return [map_incident_to_alert(inc) for inc in incidents]
