"""
Copyright start
Copyright (C) 2008 - 2024 FortinetInc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end
"""

import os
import json
from urllib.parse import quote, urlencode
from integrations.crudhub import make_request
from .connections import *
from connectors.cyops_utilities.builtins import download_file_from_cyops


def get_all_lookup_tables(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        endpoint = '/rest/pub/lookupTable'
        headers = fortisiem_obj.generate_headers()
        param_dict = {k: v for k, v in params.items() if v is not None and v != '' and v != {} and v != []}
        if param_dict != {}:
            endpoint = '{0}?{1}'.format(endpoint, urlencode(param_dict))
        response = fortisiem_obj.make_rest_call(endpoint, headers=headers, method='GET')
        return response
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def create_lookup_table(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        endpoint = '/rest/pub/lookupTable'
        headers = fortisiem_obj.generate_headers()
        headers.update({'Content-Type': 'application/json'})
        response = fortisiem_obj.make_rest_call(endpoint, headers=headers, data=json.dumps(params), method='POST')
        return response
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def delete_lookup_table(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        endpoint = '/rest/pub/lookupTable/{lookupTableId}'.format(lookupTableId=params.get('lookupTableId'))
        headers = fortisiem_obj.generate_headers()
        response = fortisiem_obj.make_rest_call(endpoint, headers=headers, params=params, method='DELETE')
        return {'message': 'Input lookup table deleted successfully', 'status': 'Success'}
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def get_csv_file_data(params):
    try:
        value = params.get('file', None)
        input_type = params.get('input', 'File IRI')
        if input_type == 'Attachment ID':
            if not value.startswith('/api/3/attachments/'):
                value = '/api/3/attachments/{0}'.format(value)
            attachment_data = make_request(value, 'GET')
            logger.info('attachment_data = {}'.format(attachment_data))
            file_iri = attachment_data['file']['@id']
            logger.info('file_iri = {0}'.format(file_iri))
        elif input_type == 'File IRI':
            if value.startswith('/api/3/files/'):
                file_iri = value
            else:
                raise ConnectorError('Invalid File IRI {0}'.format(value))
        dw_file_md = download_file_from_cyops(file_iri)
        tmp_file_path = dw_file_md.get('cyops_file_path')
        file_name = dw_file_md.get('filename')
        logger.info('file_name = {0}'.format(file_name))
        file_path = os.path.join('/tmp', tmp_file_path)
        with open(file_path, 'rb') as attachment:
            file_data = attachment.read()
        return file_name, file_data
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def import_lookup_table_data(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        endpoint = '/rest/pub/lookupTable/{0}/import'.format(params.get('lookupTableId'))
        headers = fortisiem_obj.generate_headers()

        payload = {
            'mapping': str(params.get('mapping')),
            'fileSeparator': params.get('fileSeparator') if params.get('fileSeparator') else ',',
            'fileQuoteChar': params.get('fileQuoteChar') if params.get('fileQuoteChar') else '"',
            'updateType': params.get('updateType') if params.get('updateType') else 'Overwrite',
            'skipHeader': params.get('skipHeader') if params.get('skipHeader') else False
        }
        file_name, file_data = get_csv_file_data(params)
        files = [('file', (file_name, file_data, 'text/csv'))]
        response = fortisiem_obj.make_rest_call(endpoint, headers=headers, data=payload, files=files, method='POST')
        return response
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def check_import_task_status(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        endpoint = '/rest/pub/lookupTable/{lookupTableId}/task/{taskId}'.format(lookupTableId=params.get('lookupTableId'),
                                                                                taskId=params.get('taskId'))
        headers = fortisiem_obj.generate_headers()
        headers.update({'content-type': 'application/json'})
        response = fortisiem_obj.make_rest_call(endpoint, headers=headers, method='GET')
        return response
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def get_lookup_table_data(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        endpoint = '/rest/pub/lookupTable/{lookupTableId}/data'.format(lookupTableId=params.pop('lookupTableId'))
        headers = fortisiem_obj.generate_headers()
        headers.update({'content-type': 'application/json'})
        param_dict = {k: v for k, v in params.items() if v is not None and v != '' and v != {} and v != []}
        response = fortisiem_obj.make_rest_call(endpoint, headers=headers, params=param_dict, method='GET')
        return response
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def update_lookup_table_data(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        endpoint = '/rest/pub/lookupTable/{lookupTableId}/data?key={key}'.format(
            lookupTableId=params.get('lookupTableId'),
            key=quote(str(params.get('key')).replace("'", '"')))
        headers = fortisiem_obj.generate_headers()
        headers.update({'content-type': 'application/json'})
        response = fortisiem_obj.make_rest_call(endpoint, headers=headers, data=json.dumps(params.get('columnData')),
                                                method='PUT')
        return {'response': response, 'message': 'lookup table updated successfully'}
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def delete_lookup_table_data(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        endpoint = '/rest/pub/lookupTable/{lookupTableId}/data/delete'.format(lookupTableId=params.get('lookupTableId'))
        headers = fortisiem_obj.generate_headers()
        headers.update({'content-type': 'application/json'})
        response = fortisiem_obj.make_rest_call(endpoint, headers=headers, data=json.dumps(params.get('keys_data')),
                                                method='PUT')
        return {'message': 'Input keys data deleted successfully', 'status': 'Success'}
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)
