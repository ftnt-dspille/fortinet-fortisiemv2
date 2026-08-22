"""
Copyright start
Copyright (C) 2008 - 2024 FortinetInc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end
"""

import json
from .connections import *


def _as_json(resp):
    """Normalize a make_rest_call result to a dict.

    make_rest_call already decodes JSON responses (it returns response.json()
    when the Content-Type says json) and only hands back raw text otherwise, so
    json.loads() must not be applied unconditionally -- on the dict path it
    raises TypeError and the caller reports a parse failure for a perfectly good
    response.
    """
    if isinstance(resp, (str, bytes, bytearray)):
        return json.loads(resp)
    return resp


def send_response(resp):
    try:
        res_json = _as_json(resp)
        if isinstance(res_json, dict) and res_json.get('status', '') == 'Failed':
            raise ConnectorError(res_json.get('response'))
        return res_json
    except ConnectorError:
        raise
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def get_watch_lists(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        get_watch_list_by = params.get('get_watch_list_by', 'Get All Watch Lists')
        endpoint = tmp_endpoints.get(get_watch_list_by, '/rest/watchlist/all')
        if params.get('watch_list_id'):
            endpoint = endpoint.format(watch_list_id=params.get('watch_list_id'))
        if params.get('watch_list_entry_id'):
            endpoint = endpoint.format(watch_list_entry_id=params.get('watch_list_entry_id'))
        if params.get('entryValue'):
            body = {
                'entryValue': params.get('entryValue')
            }
            resp = fortisiem_obj.make_rest_call(endpoint, params=body)
            return _as_json(resp)
        resp = fortisiem_obj.make_rest_call(endpoint)
        return send_response(resp)
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def add_watch_list_entries_to_watch_list_groups(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        endpoint = '/rest/watchlist/addTo?watchlistId={0}'.format(params.get('watch_list_id'))
        other_params = params.get('other_params', {})
        if isinstance(other_params, dict):
            other_params = [other_params]
        for item in other_params:
            if not item.get('entryValue'):
                raise ConnectorError('entryValue is required key in Other parameters')
        tmp_lst = []
        for item in other_params:
            params_list = {k: v for k, v in item.items() if v is not None and v != ''}
            tmp_lst.append(params_list)
        resp = fortisiem_obj.make_rest_call(endpoint, method='POST', data=json.dumps(tmp_lst))
        return send_response(resp)
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def create_watchlist_group(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        endpoint = '/rest/watchlist/save'
        json_object = params.get('json_object')
        if not json_object.get('displayName'):
            raise ConnectorError('displayName is required input key in watch list json object')
        if not json_object.get('type'):
            raise ConnectorError('type is required input key in watch list json object')
        entries = json_object.get('entries', [])
        for entry in entries:
            if not entry.get('entryValue') or not entry.get('dataCreationType'):
                raise ConnectorError('entryValue and dataCreationType are the required parameters in json object entry section')
        resp = fortisiem_obj.make_rest_call(endpoint, method='POST', data=json.dumps(json_object))
        return send_response(resp)
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def update_watch_list_state(fortisiem_obj, params):
    try:
        endpoint = '/rest/watchlist/entry/active/{entry_id}'.format(entry_id=params.get('watch_list_entry_id'))
        if params.get('state') == 'Active':
            param = {'state': True}
        else:
            param = {'state': False}
        resp = fortisiem_obj.make_rest_call(endpoint, method='POST', params=param)
        return resp
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def update_watch_list_entry(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        res = get_watch_list_entry(config, {'watch_list_entry_id': params.get('watch_list_entry_id')})
        input_params = res.get('response', {})
        endpoint = '/rest/watchlist/entry/save'
        if params.get('lastSeenTime'):
            input_params['lastSeen'] = params.get('lastSeenTime')

        if params.get('count'):
            input_params['count'] = params.get('count')

        if params.get('other_params'):
            input_params.update(params.get('other_params'))

        params_list = {k: v for k, v in input_params.items() if v is not None and v != ''}
        resp = fortisiem_obj.make_rest_call(endpoint, method='POST', data=json.dumps(params_list))
        send_response(resp)

        if str(params.get('state')):
            resp = update_watch_list_state(fortisiem_obj, params)
        return send_response(resp)
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def delete_watch_list_entry(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        endpoint = '/rest/watchlist/entry/delete'
        input_data = str_to_list(params.get('watch_list_entry_ids'))
        resp = fortisiem_obj.make_rest_call(endpoint, method='POST', data=json.dumps(input_data))
        return send_response(resp)
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def delete_watch_list(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        endpoint = '/rest/watchlist/delete'
        input_data = str_to_list(params.get('watch_list_ids'))
        resp = fortisiem_obj.make_rest_call(endpoint, method='POST', data=json.dumps(input_data))
        return send_response(resp)
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def get_watch_list_entry(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        endpoint = '/rest/watchlist/entry/{watch_list_entry_id}'.format(
            watch_list_entry_id = params.get('watch_list_entry_id'))
        resp = fortisiem_obj.make_rest_call(endpoint, method='GET')
        return send_response(resp)
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def get_watch_list_entries_count(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        endpoint = '/rest/watchlist/cnt'
        resp = fortisiem_obj.make_rest_call(endpoint, method='GET')
        return send_response(resp)
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)
