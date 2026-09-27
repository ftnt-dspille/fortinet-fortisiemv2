"""
Copyright start
Copyright (C) 2008 - 2026 FortinetInc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end

Operations that fortinet-fortisiem (v1) exposes and v2 had dropped.

v2 is the successor, so a playbook written against v1 must keep working once
its connector name is changed to fortinet-fortisiemv2 -- same operation names,
same parameters, same result shape. Everything here is ported from v1 6.0.0 on
top of v2's own REST client (`connections.FortiSIEM`), which is v1's with
fixes, so the wire behavior matches.

* Case management, `create_task`, `execute_api_request` -- v1 features v2 did
  not carry over. Visible in the designer: they are functionality, not aliases.
* `get_associated_events_new` -- v1's async-start variant of
  `get_associated_events`. Hidden alias: v2's `get_associated_events` already
  runs the start/progress/result lifecycle through pyfortisiem.
"""

import json
import time
from os.path import basename, exists, join

import requests
import xmltodict

from connectors.core.connector import ConnectorError, get_logger

from .connections import FortiSIEM

logger = get_logger('fortinet-fortisiemv2')

# v1 constants.WAIT_TIME / connections.MAX_RETRIES for the triggeringEvents
# poll: FortiSIEM answers 429 while a query slot is busy.
_RETRIES = 3
_RATE_LIMIT_WAIT_SECONDS = 10


def _get_with_retries(fortisiem_obj, endpoint, headers):
    """v1 `FortiSIEM.make_rest_call_with_retries`: GET JSON, retry on 429."""
    for attempt in range(1, _RETRIES + 1):
        status_code, json_resp = fortisiem_obj.make_json_rest_call(endpoint, headers=headers)
        if status_code in (200, 201, 202):
            return json_resp
        if status_code != 429:
            raise ConnectorError(f"Error: {status_code} - {json_resp}")
        logger.info(f"Rate limited 429, retrying {attempt}/{_RETRIES}...")
        if attempt < _RETRIES:
            time.sleep(_RATE_LIMIT_WAIT_SECONDS)
    raise ConnectorError(f"Rate limit error: {json_resp}")


def _wait_for_progress(fortisiem_obj, endpoint, headers, budget_seconds=100):
    """Poll a triggeringEvents progress endpoint until it reports 100."""
    deadline = time.time() + budget_seconds
    while True:
        resp = _get_with_retries(fortisiem_obj, endpoint, headers)
        pct = resp.get('progressPct') if isinstance(resp, dict) else resp
        if str(pct) == '100':
            return True
        if time.time() >= deadline:
            return False
        time.sleep(2)


def _time_ms(value):
    from .operations import convert_time_to_miliseconds
    return convert_time_to_miliseconds(value)


# ---------------------------------------------------------------------------
# Hidden alias
# ---------------------------------------------------------------------------

def get_associated_events_new(config, params):
    fortisiem_obj = FortiSIEM(config)
    headers = fortisiem_obj.generate_headers()
    headers.update({'Content-Type': 'application/json', 'Accept': 'application/json'})
    incident_id = params.get('incident_id')
    per_page = params.get('perPage') or params.get('per_page') or 10
    endpoint = f'/rest/pub/incident/triggeringEvents/start?incidentId={incident_id}&size={per_page}'
    time_from, time_to = _time_ms(params.get('timeFrom')), _time_ms(params.get('timeTo'))
    if time_from:
        endpoint += f'&timeFrom={time_from}'
    if time_to:
        endpoint += f'&timeTo={time_to}'
    query_id = _get_with_retries(fortisiem_obj, endpoint, headers)
    # FortiSIEM 7.5+ wraps the id: {"queryId": ...}
    if isinstance(query_id, dict):
        query_id = query_id.get('queryId')
    if not _wait_for_progress(fortisiem_obj,
                              f'/rest/pub/incident/triggeringEvents/progress/{query_id}',
                              headers):
        raise ConnectorError('Query progress status is still in progress')
    resp = _get_with_retries(
        fortisiem_obj, f'/rest/pub/incident/triggeringEvents/result/{query_id}?size={per_page}', headers)
    if isinstance(resp, dict) and resp.get('data'):
        resp = resp.get('data', [])
    return resp


# ---------------------------------------------------------------------------
# Generic REST
# ---------------------------------------------------------------------------

def execute_api_request(config, params):
    fortisiem_obj = FortiSIEM(config)
    endpoint = params.get('endpoint', '')
    headers = fortisiem_obj.generate_headers()
    if params.get('content_type'):
        headers['Content-Type'] = params.get('content_type')
    payload = params.get('payload')
    data = json.dumps(payload) if payload else None
    if not endpoint.startswith('/'):
        endpoint = f'/{endpoint}'
    resp = fortisiem_obj.make_rest_call(endpoint, headers=headers, params=params.get('query_params') or {},
                                        method=params.get('method') or 'GET', data=data)
    if isinstance(resp, str) and resp:
        try:
            return xmltodict.parse(resp)
        except Exception:
            try:
                return json.loads(resp)
            except Exception:
                return resp
    return resp


def create_task(config, params):
    if not params.get('task_metadata') or not params.get('triggeredByUser'):
        # v1 raised NameError here (it logged an undefined `err`).
        raise ConnectorError('task_metadata and triggeredByUser are required')
    data = {
        'task_metadata': params.get('task_metadata', {}),
        'triggeredByUser': params.get('triggeredByUser'),
        'assignedToUser': params.get('assignedToUser'),
        'comment': params.get('comment'),
    }
    try:
        fortisiem_obj = FortiSIEM(config)
        headers = fortisiem_obj.generate_headers()
        headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
        return fortisiem_obj.make_rest_call('/rest/permission/save', headers=headers,
                                            data=json.dumps(data), method='POST')
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


# ---------------------------------------------------------------------------
# Case management
# ---------------------------------------------------------------------------

def _epoch(date_str, milli_seconds=False):
    from datetime import datetime
    try:
        seconds = int(datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S.%fZ').timestamp())
        return seconds * 1000 if milli_seconds else seconds
    except Exception as e:
        logger.error(e)
        return date_str


def _case_payload(params):
    incident_ids = params.get('incidentIds')
    if incident_ids and isinstance(incident_ids, str):
        params['incidentIds'] = incident_ids.split(',')
    elif incident_ids and isinstance(incident_ids, int):
        params['incidentIds'] = [incident_ids]
    if params.get('dueDate'):
        params['dueDate'] = _epoch(params['dueDate'], milli_seconds=True)
    return {k: v for k, v in params.items() if v not in (None, '', {}, [])}


def _rows_to_dicts(resp_data):
    """v1 `process_response_data`: CMDB rows + columnNames -> list of dicts."""
    if resp_data and isinstance(resp_data.get('data'), list):
        cols = resp_data.get('columnNames') or []
        resp_data['data'] = [dict(zip(cols, row)) for row in resp_data['data']]
    return resp_data


def create_case(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        headers = fortisiem_obj.generate_headers()
        headers.update({'Content-Type': 'application/json'})
        return fortisiem_obj.make_rest_call('/rest/pub/case', headers=headers,
                                            data=json.dumps(_case_payload(params)), method='POST')
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def update_cases(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        case_id = params.pop('caseId', '')
        headers = fortisiem_obj.generate_headers()
        headers.update({'Content-Type': 'application/json'})
        return fortisiem_obj.make_rest_call(f'/rest/pub/case/{case_id}', headers=headers,
                                            data=json.dumps(_case_payload(params)), method='PUT')
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def get_case_analysts(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        query_params = _case_payload(params)
        if params.get('timeTo'):
            query_params['timeTo'] = _epoch(params['timeTo'])
        if params.get('timeFrom'):
            query_params['timeFrom'] = _epoch(params['timeFrom'])
        return fortisiem_obj.make_rest_call('/rest/pub/case/analysts', headers=fortisiem_obj.generate_headers(),
                                            params=query_params, method='GET')
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def _file_from_iri(iri):
    from connectors.cyops_utilities.builtins import download_file_from_cyops
    from integrations.crudhub import make_request
    iri_type = 'file' if iri.startswith('/api/3/files') else 'attachment'
    if not iri.startswith('/api/3/'):
        iri = '/api/3/attachments/' + iri
    try:
        file_iri = make_request(iri, 'GET')['file']['@id'] if iri_type == 'attachment' else iri
        downloaded = download_file_from_cyops(file_iri)
        return _file_from_path(join('/tmp', downloaded.get('cyops_file_path')), downloaded.get('filename'))
    except ConnectorError:
        raise
    except Exception as err:
        logger.exception(f"Error occurred: {err}")
        raise ConnectorError(f"Error while processing the file: {err}")


def _file_from_path(file_path, file_name=''):
    file_path = file_path if file_path.startswith('/tmp') else join('/tmp', file_path)
    if not exists(file_path):
        raise ConnectorError(f"File at {file_path} does not exist.")
    with open(file_path, 'rb') as fp:
        return file_name or basename(file_path), fp.read() or b''


def upload_attachment_for_case(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        case_id = params.get('caseID')
        if params.get('upload_option') == 'IRI':
            file_name, file_data = _file_from_iri(params.get('file_iri'))
        else:
            file_name, file_data = _file_from_path(params.get('file_path'))
        if not file_data:
            raise ConnectorError("File data is missing or empty")
        resp = fortisiem_obj.make_rest_call(f'/rest/pub/case/{case_id}/attachment',
                                            headers=fortisiem_obj.generate_headers(), method='POST',
                                            files=[('file', (file_name, file_data))])
        if isinstance(resp, requests.Response) and not resp.text:
            return {'status': 'success',
                    'message': f'file successfully uploaded as an attachment in the case: {case_id}'}
        return resp
    except Exception as err:
        logger.error(f"Error uploading attachment: {err}")
        raise ConnectorError(f"Error uploading attachment: {err}")


def get_list_cases(config, params):
    fortisiem_obj = FortiSIEM(config)
    org = (params.get('runForOrganization') or '').strip()
    if org:
        params['runForOrganization'] = [org]
    order_by = (params.get('orderBy') or '').strip()
    if order_by:
        params['orderBy'] = [order_by]
    query_params = {k: v for k, v in {'size': params.get('size'), 'start': params.get('start')}.items()
                    if v not in (None, '', {}, [])}
    headers = fortisiem_obj.generate_headers()
    headers.update({'Content-Type': 'application/json'})
    payload = {k: v for k, v in params.items() if v not in (None, '', {}, [])}
    select_fields = payload.pop('selectFields', '')
    if isinstance(select_fields, str) and select_fields:
        select_fields = select_fields.split(',')
    if isinstance(select_fields, list):
        select_fields = [f.strip() for f in select_fields]
    payload['selectFields'] = select_fields
    payload['target'] = 'CASE'
    resp = fortisiem_obj.make_rest_call('/rest/query/cmdb', headers=headers, method='POST',
                                        params=query_params, data=json.dumps(payload))
    resp = json.loads(resp) if not isinstance(resp, (dict, list)) else resp
    return _rows_to_dicts(resp)


def get_case_field_schema(config, params):
    fortisiem_obj = FortiSIEM(config)
    resp = fortisiem_obj.make_rest_call('/rest/query/cmdb/schema', headers=fortisiem_obj.generate_headers(),
                                        method='GET', params={'target': 'CASE'})
    return json.loads(resp) if not isinstance(resp, (dict, list)) else resp


V1_COMPAT_OPERATIONS = {
    'get_associated_events_new': get_associated_events_new,
    'execute_api_request': execute_api_request,
    'create_task': create_task,
    'create_case': create_case,
    'update_cases': update_cases,
    'get_case_analysts': get_case_analysts,
    'upload_attachment_for_case': upload_attachment_for_case,
    'get_list_cases': get_list_cases,
    'get_case_field_schema': get_case_field_schema,
}
