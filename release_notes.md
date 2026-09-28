#### 6.1.2

- The Data Ingestion sample playbooks now build with the current version in
  the collection name, so they auto-import on connector upgrade. Previously the
  committed `playbooks.json` was still stamped for 6.0.4; FortiSOAR deletes a
  connector's sample collection on upgrade and re-imports it under the new
  version-derived name, so the ingestion playbooks (Fetch / Ingest / Init
  Macros) were missing after updating. The wizard contract
  (`exported_tags`, the Fetch config schema, and the Ingest Execute-menu
  trigger) is now expressed in the YAML source and compiled natively, with
  `playbooks/build.py` reduced to deterministic version stamping.

#### 6.1.1

- A non-JSON error body now reaches the caller as itself. FortiSIEM answers some
  bad requests (an incident id that is not an integer, for one) with plain text,
  and the JSON REST path parsed the body even to log it. The real error was lost
  behind "Expecting value: line 1 column 1". Bare JSON-string responses (the
  pre-7.5 query id) still decode as before.

#### 6.1.0

- v2 now runs playbooks written for `fortinet-fortisiem` (v1) with only the
  connector name changed. Every v1 6.0.0 operation exists here under the same
  name and accepts the same parameters:
  - Case management (`create_case`, `update_cases`, `get_list_cases`,
    `get_case_analysts`, `get_case_field_schema`, `upload_attachment_for_case`),
    `create_task` and `execute_api_request` are ported from v1 onto v2's REST
    client.
  - `run_report` accepts v1's `query_type: SQL Query` / `sql_query` (ClickHouse
    SQL report). Omitting `query_type` keeps the attribute/condition form.
  - `get_associated_events_new` is a hidden alias. New playbooks should use
    `get_associated_events`, which already runs the start/progress/result
    lifecycle.
  - `update_incident` declares v1's `actionStatus`.
- Fix: `get_associated_events` ignored its page size. info.json names the
  parameter `per_page`, but the code read only `perPage`. Both spellings now work.
- `create_task` with no metadata raises a clear error. The v1 code it was ported
  from failed with a NameError there.

#### 6.0.4

- Fixes a regression in 6.0.2: `sourcedata` was stored as the literal string
  `Array` on every alert. 6.0.2 had the mapper pre-serialise the payload and
  the playbook assign it with a bare `{{ }}`, which makes FortiSOAR parse the
  leading `{...}` and collapse the value -- the same trap the rendered
  description hit in 6.0.1. The mapper now emits `source_payload` as a dict
  and the playbook renders it with `| toJSON`, which keeps the description out
  of the blob without tripping the parse.

#### 6.0.3

- Ingestion no longer cold-starts forever when the watermark macro is missing.
  `Environment Setup` ran only on the wizard's `vars.request.env_setup` first
  pass, and `Update Last Alert Pull Time` only updates an existing macro -- so a
  configuration whose macro never got created would re-read the same `minutes`
  window on every run and silently ingest nothing. Observed on a live 8.0.0
  appliance as 100 scheduled runs, all reporting `finished`, with zero records
  created. `Get Macro Value` now runs first so the macro's absence is visible,
  and `Environment Setup` fires on that condition too.

#### 6.0.2

- `sourcedata` no longer carries a second copy of the rendered `description`.
  It is serialised in `field_mapping` with that key excluded, instead of by
  `| toJSON` in the ingestion playbook. The HTML is presentation derived from
  values already in the payload, and storing it twice accounted for roughly
  30% of every alert's source data.

#### 6.0.1

Alert field mapping.

- `description` is now rich text built from the incident (headline, overview
  table, MITRE ATT&CK list, incident detail) instead of FortiSIEM's raw
  `incidentDetail` JSON. The raw value was being parsed by FortiSOAR's
  templating and collapsed to the literal string `Array` on every alert.
- `alert_type` now resolves only to members of the `AlertType` picklist. It
  previously emitted `Security`, `Availability`, `Change` and
  `Anomaly Detection`, none of which are picklist values.
- The ingestion playbook maps `type`, `alertDetectionDate`, `eventTime`,
  `hostName`, `hostIPAddress`, `destinationIp`, `destinationPort`,
  `mitreattackid` and `mitreTechnique` in addition to the previous fields.
- Incident timestamps are also emitted as epoch seconds
  (`alert_generation_epoch`, `last_observed_epoch`) so the playbook assigns
  FortiSOAR's integer date columns directly.

#### What's Fixed
- Added a parameter Group By in the action Run Advanced Search Query.
- Fixed the issue where widget spinner would always show the following message on the alert's detailed view when an alert was updated during re-ingestion: Please wait while Indicators are being extracted. NOTE: You need to reconfigure data ingestion for this to work.

> **Notes**
> - Only FortiSIEM versions 7.1.0 and later are supported by this connector version.
> - The FortiSIEM API no longer supports filtering incidents based on sub-categories in the List Incidents action.
> - The Time From and Time To parameters in the Get Events For Incident action are supported only in the FortiSIEM v6.7.6.
