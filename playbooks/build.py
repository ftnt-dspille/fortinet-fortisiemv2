#!/usr/bin/env python3
"""Build playbooks.json from playbooks.yaml.

Compiles the YAML with the fsrpb compiler, then patches on the three pieces of
the Data Ingestion Wizard contract that the YAML dialect has no spelling for:

  1. collection-level ``exported_tags`` -- the wizard filters the connector's
     playbook export by these before it will offer an ingestion configuration;
  2. ``_configuration_schema`` on the Fetch playbook's Start step -- the JSON
     that renders the wizard's configuration form;
  3. the manual-trigger fields on the Ingest playbook's Start step (``route``,
     ``resources``, ``displayConditions``, ``noRecordExecution`` ...) which the
     FortiSOAR designer normally synthesizes.

Usage:  python playbooks/build.py [--fsrpb /path/to/fsrpb]
"""

import argparse
import json
import pathlib
import os
import re
import subprocess
import sys
import uuid

HERE = pathlib.Path(__file__).resolve().parent
YAML_IN = HERE / "playbooks.yaml"
JSON_OUT = HERE / "playbooks.json"

CONNECTOR = "fortinet-fortisiemv2"

EXPORTED_TAGS = [CONNECTOR, "Fortinet", "dataingestion", "fetch", "create", "ingest"]

FETCH_PLAYBOOK = "> FortiSIEM v2 > Fetch"
INGEST_PLAYBOOK = "FortiSIEM v2 > Ingest"

# Rendered as the wizard's configuration form. Mirrors the params that the
# Fetch playbook's `Configuration` set_variable step defaults.
CONFIGURATION_SCHEMA = [
    {
        "title": "Fetch Mode",
        "required": True,
        "editable": True,
        "visible": True,
        "type": "select",
        "name": "fetch_mode",
        "options": ["By Updates In Last X Minutes", "By Sample Incident ID"],
        "onchange": {
            "By Updates In Last X Minutes": [
                {
                    "title": "Pull Incidents Created/Updated In Last X Minutes",
                    "name": "minutes",
                    "type": "text",
                    "required": True,
                    "editable": True,
                    "visible": True,
                    "value": 10,
                    "tooltip": "Cold-start lookback used on the first run, before a "
                               "last-pull-time watermark exists. e.g. 10",
                },
                {
                    "title": "Incident Status",
                    "name": "incidentStatus",
                    "type": "multiselect",
                    "required": False,
                    "editable": True,
                    "visible": True,
                    "value": ["Active"],
                    "options": ["Active", "Auto Cleared", "Manually Cleared",
                                "System Cleared"],
                },
                {
                    "title": "Severity",
                    "name": "severity",
                    "type": "multiselect",
                    "required": False,
                    "editable": True,
                    "visible": True,
                    "value": ["High", "Medium", "Low"],
                    "options": ["High", "Medium", "Low"],
                },
                {
                    "title": "Incident Category",
                    "name": "incidentCategory",
                    "type": "multiselect",
                    "required": False,
                    "editable": True,
                    "visible": True,
                    "options": ["Availability", "Performance", "Change",
                                "Security", "Other"],
                },
                {
                    "title": "Incidents Per Page",
                    "name": "size",
                    "type": "text",
                    "required": False,
                    "editable": True,
                    "visible": True,
                    "value": 100,
                    "tooltip": "Page size for the incident query. The run pages "
                               "through the whole window, so this tunes request "
                               "batching -- it is not a cap on incidents ingested.",
                },
                {
                    "title": "Fetch Triggering Events",
                    "name": "include_events",
                    "type": "checkbox",
                    "required": False,
                    "editable": True,
                    "visible": True,
                    "value": True,
                    "tooltip": "Enrich each incident with its triggering events. "
                               "Adds roughly one FortiSIEM query per incident.",
                },
                {
                    "title": "Maximum Events To Pull Per Incident",
                    "name": "event_count",
                    "type": "text",
                    "required": False,
                    "editable": True,
                    "visible": True,
                    "value": 5,
                },
            ],
            "By Sample Incident ID": [
                {
                    "title": "Incident ID",
                    "name": "incidentId",
                    "type": "text",
                    "required": True,
                    "editable": True,
                    "visible": True,
                    "tooltip": "Incident ID to use for building the field mapping",
                },
                {
                    "title": "From",
                    "name": "from",
                    "type": "datetime",
                    "required": False,
                    "editable": True,
                    "visible": True,
                },
                {
                    "title": "To",
                    "name": "to",
                    "type": "datetime",
                    "required": False,
                    "editable": True,
                    "visible": True,
                },
            ],
        },
    },
]


def _iter_workflows(doc):
    for coll in doc.get("data", []):
        for wf in coll.get("workflows", []):
            yield coll, wf


def _start_step(wf):
    for step in wf.get("steps", []):
        if step.get("name") == "Start":
            return step
    raise SystemExit(f"no Start step in playbook {wf['name']!r}")


def patch(doc):
    """Apply the wizard-contract patches in place."""
    doc["exported_tags"] = list(EXPORTED_TAGS)

    seen = set()
    for _coll, wf in _iter_workflows(doc):
        name = wf.get("name")
        if name == FETCH_PLAYBOOK:
            args = _start_step(wf).setdefault("arguments", {})
            sv = args.setdefault("step_variables", {})
            if not isinstance(sv, dict):
                sv = {"input": {"params": []}}
                args["step_variables"] = sv
            sv["_configuration_schema"] = json.dumps(CONFIGURATION_SCHEMA, indent=2)
            seen.add(name)
        elif name == INGEST_PLAYBOOK:
            step = _start_step(wf)
            args = step.setdefault("arguments", {})
            # Deterministic route id so re-running the build does not churn the
            # diff or orphan the wizard's binding.
            args["route"] = str(uuid.uuid5(uuid.NAMESPACE_URL,
                                           f"{CONNECTOR}/{INGEST_PLAYBOOK}/route"))
            args["title"] = INGEST_PLAYBOOK
            args["resources"] = ["alerts"]
            args["inputVariables"] = []
            args["displayConditions"] = {
                "alerts": {"sort": [], "limit": 30, "logic": "AND", "filters": []},
            }
            args["executeButtonText"] = "Execute"
            args["noRecordExecution"] = True
            args["singleRecordExecution"] = False
            args.setdefault("step_variables", {})["input"] = {
                "records": "{{vars.input.records}}",
            }
            seen.add(name)

    missing = {FETCH_PLAYBOOK, INGEST_PLAYBOOK} - seen
    if missing:
        raise SystemExit(f"expected playbooks not found in compiled output: {sorted(missing)}")
    return doc


def _freeze_timestamps(doc):
    """Pin every ``lastModifyDate`` so a rebuild is byte-identical.

    The compiler stamps each workflow with the wall-clock time of the build, so
    two runs over an unchanged source produce two different files -- 54 lines of
    diff across the 27 playbooks, carrying no information. That noise hides the
    one-line change you actually made when reviewing, and makes it impossible to
    tell from a diff whether the compiled artefact was rebuilt or edited.

    The value tracks the YAML's own mtime, so it still moves when the source
    genuinely changes. ``SOURCE_DATE_EPOCH`` overrides it, per the usual
    reproducible-builds convention.
    """
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    stamp = int(epoch) if epoch and epoch.isdigit() else int(YAML_IN.stat().st_mtime)

    def walk(node):
        if isinstance(node, dict):
            if "lastModifyDate" in node:
                node["lastModifyDate"] = stamp
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(doc)
    return doc


def _sync_collection_version(doc):
    """Retag the sample collection with the version from ``info.json``.

    FortiSOAR deletes a connector's sample collection on upgrade and re-imports
    it under the new name, so a collection still carrying the previous version
    leaves the appliance with a stale name -- or, if the old collection was
    removed by hand, no ingestion playbooks at all.  Keeping the name derived
    from ``info.json`` means the version only has to be bumped in one place.
    """
    info = json.loads((HERE.parent / "info.json").read_text())
    version = info.get("version")
    if not version:
        return doc
    for collection in doc.get("data", []):
        name = collection.get("name") or ""
        collection["name"] = re.sub(r"\d+\.\d+\.\d+$", version, name) if re.search(
            r"\d+\.\d+\.\d+$", name) else name
    return doc


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--fsrpb", default="fsrpb", help="path to the fsrpb executable")
    args = ap.parse_args()

    def _compile(lax):
        cmd = [args.fsrpb, "compile", str(YAML_IN), "-o", str(JSON_OUT)]
        if lax:
            cmd.insert(3, "--lax")
        return subprocess.run(cmd, capture_output=True, text=True)

    proc = _compile(lax=False)
    if proc.returncode != 0 and "unknown connector" in (proc.stdout + proc.stderr):
        # The reference store has not been told about this connector yet, so
        # every step referencing it fails validation. Fall back to --lax so the
        # build still works, but say how to fix it properly -- under --lax a
        # genuinely misspelled operation slips through as a warning too.
        sys.stderr.write(
            f"warning: the fsrpb catalog does not know {CONNECTOR!r}; compiling "
            f"with --lax, which also demotes real typos to warnings.\n"
            f"         fix: fsrpb provision {HERE.parent}\n",
        )
        proc = _compile(lax=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout + proc.stderr)
        return proc.returncode

    doc = json.loads(JSON_OUT.read_text())
    doc = _sync_collection_version(doc)
    doc = _freeze_timestamps(doc)
    JSON_OUT.write_text(json.dumps(patch(doc), indent=2) + "\n")

    total = sum(len(c.get("workflows", [])) for c in doc.get("data", []))
    print(f"wrote {JSON_OUT} ({total} playbooks, exported_tags={EXPORTED_TAGS})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
