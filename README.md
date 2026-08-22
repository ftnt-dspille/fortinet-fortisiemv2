# Fortinet FortiSIEM v2 -- FortiSOAR connector

A FortiSOAR connector for FortiSIEM, built on the typed
[`pyfortisiem`](https://pypi.org/project/pyfortisiem/) client. It covers
incident and event retrieval, entity context, watch lists, lookup tables,
CMDB/ClickHouse queries, credential management, and native data ingestion.

## Data ingestion

`ingest_incidents` pages `/pub/incident`, maps each incident onto the
FortiSOAR alert shape, and optionally enriches it with triggering events. The
playbooks under `playbooks/` implement the Data Ingestion Wizard contract:
`> FortiSIEM v2 > Fetch` reads a last-pull-time watermark and fetches the
window, `FortiSIEM v2 > Ingest` upserts the alerts and advances the watermark.

Two things about the mapping are deliberate and easy to undo by accident:

- `description` is **rich text built by `field_mapping.build_description`**,
  not FortiSIEM's raw `incidentDetail`. That raw value is a JSON *string*, and
  FortiSOAR's templating parses its leading `{...}` and stores the whole field
  as the literal text `Array`. Braces in interpolated values are escaped to
  entities for the same reason -- Windows command lines carry GUIDs in braces.
- `sourcedata` is rendered from `source_payload` with `| toJSON`. Passing
  already-serialised JSON through a bare `{{ }}` hits that same parse.

`alert_type` is clamped to `VALID_ALERT_TYPES`. An unmapped value makes the
playbook's `resolveRange` miss and the alert POST fails with a picklist 400.

## Playbooks

`playbooks/playbooks.yaml` is the source of truth; `playbooks.json` is
generated:

```bash
python playbooks/build.py          # needs the fsrpb compiler on PATH
```

The build stamps the sample collection with the version from `info.json`.
Note it mints fresh step UUIDs per run, so it is not byte-reproducible.

## Releasing

`scripts/package.sh` builds the bundle FortiSOAR installs -- the git-tracked
files minus tests, `playbooks/build.py` and repo furniture, staged under a
single `fortinet-fortisiemv2/` directory:

```bash
./scripts/package.sh        # -> dist/fortinet-fortisiemv2-<version>.tgz
```

Pushing a `v<version>` tag runs the same script in CI and attaches the result
to a GitHub release. `info.json` stays the source of truth for the version; the
workflow refuses a tag that disagrees with it, a `playbooks.json` still built
for an older version, and any en/em dash.

```bash
git tag v6.0.4 && git push origin v6.0.4
```

## Tests

```bash
pytest tests/test_offline.py       # no appliance needed
cp tests/.env.example tests/.env   # then fill in, for the live suite
pytest tests/test_live.py
```

## Avoid en/em dashes

FortiSOAR loads connector source as latin-1 at runtime, so a `--` or `-`
anywhere in this tree raises
`'latin-1' codec can't encode character '-'`. Use `--` and `-`.
