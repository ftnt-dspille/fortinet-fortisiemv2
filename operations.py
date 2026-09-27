"""
Copyright start
Copyright (C) 2008 - 2024 FortinetInc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end
"""

from .attributes_list import *
from .lookup_table_actions import *
from .schema import report_schema, schema_by_event_id, search_event_schema, sql_query_schema
from .watch_list_actions import *
from .ingestion import ingest_incidents
from .utils import DATETIME_PATTERNS, parse_datetime_to_epoch
from .field_mapping import map_incident_to_alert, parse_mitre, parse_attrib_pairs
from .v1_compat import V1_COMPAT_OPERATIONS

requests.packages.urllib3.disable_warnings()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def convert_time_to_miliseconds(input_datetime):
    """Convert an ISO-ish datetime to epoch milliseconds ('' when not supplied).

    Delegates to the shared parser so second-precision timestamps (what the
    ingestion playbook emits) are accepted and the result is UTC rather than
    appliance-local.
    """
    if not input_datetime:
        return ''
    epoch = parse_datetime_to_epoch(input_datetime)
    if epoch is None:
        raise ConnectorError(
            "Unrecognised datetime {0!r}; expected one of {1}".format(
                input_datetime, ', '.join(DATETIME_PATTERNS)))
    return epoch * 1000


def update_attr_data(incident_type, incident, key=None):
    attribPairs = incident_type.split(',')
    attrib_dict = {}
    for attribPair in attribPairs:
        if ":" not in attribPair:
            continue
        index = attribPair.index(":")
        attribName = attribPair[0:index].strip()
        attribValue = attribPair[index + 1:].strip()
        if key:
            attrib_dict[attribName] = attribValue
        else:
            incident[attribName] = attribValue
    incident[key] = attrib_dict
    return incident


# ---------------------------------------------------------------------------
# Legacy XML-based operations (kept for backward compatibility)
# These use the FortiSIEM class from connections.py with requests + xmltodict
# ---------------------------------------------------------------------------

def get_devices_details(config, params):
    fortisiem_obj = FortiSIEM(config)
    params['organization'] = params.get('org', None)
    endpoint = '/rest/cmdbDeviceInfo/devices'
    resp = fortisiem_obj.make_rest_call(endpoint, params=params)
    response = xmltodict.parse(resp)
    if response.get('response'):
        return response['response']['error']['description']
    return response if response.get('devices') else {'devices': {'device': [response['device']]}}


def get_device_info(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        endpoint = '/rest/cmdbDeviceInfo/device'
        params_dict = {
            'organization': params.get('org'),
            'loadDepend': True,
            'ip': params.get('ip')
        }
        resp = fortisiem_obj.make_rest_call(endpoint, params_dict)
        return xmltodict.parse(resp)
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def get_monitored_devices(config, params):
    fortisiem_obj = FortiSIEM(config)
    endpoint = '/rest/deviceInfo/monitoredDevices'
    resp = fortisiem_obj.make_rest_call(endpoint)
    res_json = xmltodict.parse(resp)
    return res_json


def get_monitored_organizations(config, params):
    fortisiem_obj = FortiSIEM(config)
    return monitored_org(fortisiem_obj)


def get_org_name_by_org_id(config, params):
    fortisiem_obj = FortiSIEM(config)
    org_list = monitored_org(fortisiem_obj)
    domain_id = str(params.get('domain_id'))
    for domain in org_list:
        if domain_id == str(domain['domainId']):
            return domain
    return 'Organization not found for provided organization ID {0}'.format(domain_id)


def run_report(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        # v1 parity: `query_type: SQL Query` runs a ClickHouse SQL report.
        # Absent or `Basic Query` is the attribute/condition form, which is
        # all v2 used to accept -- so existing v2 playbooks are unaffected.
        if (params.get('query_type') or '').lower() == 'sql query':
            if not params.get('sql_query'):
                raise ConnectorError('sql_query is required when query_type is SQL Query')
            xml_request_payload = sql_query_schema.format(sql_query=params.get('sql_query'))
        else:
            xml_request_payload = report_schema.format(
                AttrList=params.get('AttrList') if params.get('AttrList') else '',
                orderby=params.get('orderby') if params.get('orderby') else '',
                conditions=params.get('cond', ''), groupby=params.get('groupby', ''),
                time_duration=handle_time(params))
        xml_request_payload = xml_request_payload.replace('None', '')
        query_id, headers = get_event_query(fortisiem_obj, xml_request_payload)
        query_id = parse_query_progress(query_id)
        query_status = get_query_progress_status(fortisiem_obj, query_id, headers)
        if query_status:
            incidents_records = get_records(fortisiem_obj, headers, query_id, params.get('start'),
                                            params.get('perPage'))
            return make_output(incidents_records, query_id)
        else:
            raise ConnectorError('Query progress status is still in progress')
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def get_event_details(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        time_xml = calculate_epoc_time(params)
        res = _get_event_details(fortisiem_obj, time_xml, params)
        if res == []:
            return {}
        else:
            return res[0]
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def _get_event_details(fortisiem_obj, time_xml, params):
    try:
        build_xml = '(eventId IN ({})  AND  phEventCategory &gt;= 0)'.format(
            params.get('event_id'))
        xml_payload = schema_by_event_id.format(eventId=build_xml, select_clause=params.get("select_clause"),
                                                time_duration=time_xml)

        query_id, headers = get_event_query(fortisiem_obj, xml_payload)
        query_id = parse_query_progress(query_id)
        query_status = get_query_progress_status(fortisiem_obj, query_id, headers)
        if query_status:
            incidents_records = get_records(fortisiem_obj, headers, query_id, params.get('start'),
                                            params.get('perPage'))
            final_result = make_output(incidents_records, query_id)
            return final_result.get('events')
        else:
            raise ConnectorError('Query progress status is still in progress')
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def search_events(config, params):
    try:
        attribute = params.get('attribute')
        temp_str = ''
        report_name = ''
        fortisiem_obj = FortiSIEM(config)
        if type(attribute) is list:
            for item in attribute:
                report_name = report_name + item
                temp = (item.replace(' ', '_')).replace('-', '_').lower()
                param_value = temp + "_value"
                if param_value == "event_action_value":
                    op_value = event_mapping.get(params.get(temp + "_value"))
                else:
                    op_value = params.get(temp + "_value")
                    if isinstance(op_value, list):
                        op_value = (','.join(str(x) for x in op_value))
                temp_str = temp_str + attribute_mapping.get(item).format(op_value) + ' AND '
        temp_str = temp_str[:-5]
        logger.info('Query string is = {}'.format(temp_str))
        xml_request_payload = search_event_schema.format(queryString=temp_str, reportName=report_name,
                                                         time_duration=handle_time(params),
                                                         select_clause=params.get('select_clause'))
        xml_request_payload = xml_request_payload.replace('None', '')
        query_id, headers = get_event_query(fortisiem_obj, xml_request_payload)
        query_id = parse_query_progress(query_id)
        query_status = get_query_progress_status(fortisiem_obj, query_id, headers)
        if query_status:
            incidents_records = get_records(fortisiem_obj, headers, query_id, params.get('start'),
                                            params.get('perPage'))
            return make_output(incidents_records, query_id)
        else:
            raise ConnectorError('Query progress status is still in progress')
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def get_events_by_query_id(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        headers = fortisiem_obj.generate_headers()
        headers['Content-Type'] = 'text/xml'
        query_id = ','.join(map(str, params.get('query_id'))) if isinstance(params.get('query_id'), list) \
            else params.get('query_id')
        query_id = parse_query_progress(query_id)
        incidents_records = get_records(fortisiem_obj, headers, query_id, params.get('start'), params.get('perPage'))
        return make_output(incidents_records, query_id)
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def get_incident_attributes(config, params):
    return attribute_list


def get_ip_context(config, params):
    fortisiem_obj = FortiSIEM(config)
    headers = fortisiem_obj.generate_headers()
    headers.update({"Accept": "application/json", "Content-Type": "application/json"})
    return fortisiem_obj.make_rest_call("/rest/context/ip", headers=headers, method="GET", params=params)


def get_host_context(config, params):
    fortisiem_obj = FortiSIEM(config)
    headers = fortisiem_obj.generate_headers()
    headers.update({"Accept": "application/json", "Content-Type": "application/json"})
    return fortisiem_obj.make_rest_call("/rest/context/hostname", headers=headers, method="GET", params=params)


def get_user_context(config, params):
    fortisiem_obj = FortiSIEM(config)
    headers = fortisiem_obj.generate_headers()
    headers.update({"Accept": "application/json", "Content-Type": "application/json"})
    return fortisiem_obj.make_rest_call("/rest/context/user", headers=headers, method="GET", params=params)


# ---------------------------------------------------------------------------
# Incident operations -- revamped to use pyfortisiem AsyncFortiSIEMClient
# ---------------------------------------------------------------------------

def async_get_incidents_rest(config, params):
    """Get incidents with optional event enrichment using pyfortisiem async client.

    Replaces the deprecated ``asyncio.new_event_loop()`` anti-pattern with
    ``run_async()`` which uses ``asyncio.run()``.
    """
    from .connections import get_async_client, run_async
    start_time_epoc = get_epoch(params.get("from"))
    end_time_epoc = get_epoch(params.get("to"))
    include_events = params.get("include_events", False)
    event_count = params.get("event_count", 5)
    per_page = params.get("per_page", 500) or 500
    start = params.get("start", 0)

    status = params.get("incidentStatus")
    status_codes = []
    if status:
        for s in (status if isinstance(status, list) else [status]):
            code = PARAMS_MAPPING.get(s)
            if code is not None:
                status_codes.append(int(code))
    if not status_codes:
        status_codes = [0]

    extra_filters = {}
    if params.get("incidentCategory"):
        cat_codes = []
        for c in params.get("incidentCategory"):
            code = INCIDENT_CATEGORY_MAPPING.get(c)
            if code is not None:
                cat_codes.append(code)
        if cat_codes:
            extra_filters["phIncidentCategory"] = cat_codes
    if params.get("severity"):
        extra_filters["eventSeverityCat"] = params.get("severity")

    return run_async(_async_get_incidents_rest_impl(
        config, start_time_epoc * 1000, end_time_epoc * 1000,
        status_codes, extra_filters, include_events, event_count, per_page,
    ))


async def _async_get_incidents_rest_impl(
    config, time_from, time_to, status_codes, extra_filters,
    include_events, event_count, per_page,
):
    """Async implementation of async_get_incidents_rest using pyfortisiem."""
    from .connections import get_async_client
    async with get_async_client(config) as fsm:
        if include_events:
            incidents = await fsm.list_incidents_with_events(
                time_from=time_from, time_to=time_to,
                status=status_codes, size=per_page,
                events_per_incident=event_count,
                extra_filters=extra_filters or None,
            )
            return [_incident_with_events_to_dict(inc) for inc in incidents]
        else:
            incidents = await fsm.list_incidents(
                time_from=time_from, time_to=time_to,
                status=status_codes, size=per_page,
                extra_filters=extra_filters or None,
            )
            return [_incident_to_dict(inc) for inc in incidents]


def get_incidents(config, params):
    """List incidents with filtering -- uses pyfortisiem async client.

    Supports all the same filters as the legacy version (status, category,
    severity, eventType, custom search) but via the fast JSON pub API
    instead of the slow XML query lifecycle.
    """
    from .connections import get_async_client, run_async

    time_from = convert_time_to_miliseconds(params.get('timeFrom'))
    time_to = convert_time_to_miliseconds(params.get('timeTo'))

    status_codes = []
    if params.get('incidentStatus'):
        for item in params.get('incidentStatus'):
            code = PARAMS_MAPPING.get(item)
            if code is not None:
                status_codes.append(int(code))

    extra_filters = {}
    if params.get('search') and isinstance(params.get('search'), dict):
        extra_filters.update(params['search'])
    if params.get('incidentCategory'):
        category_list = []
        for item in params.get('incidentCategory'):
            code = INCIDENT_CATEGORY_MAPPING.get(item)
            if code is not None:
                category_list.append(code)
        if category_list:
            extra_filters['phIncidentCategory'] = category_list
    if params.get('incidentSubCategory'):
        from .utils import str_to_list_for_stings
        extra_filters['phSubIncidentCategory'] = str_to_list_for_stings(params.get('incidentSubCategory'))
    if params.get('severity'):
        extra_filters['eventSeverityCat'] = params.get('severity')
    if params.get('eventType'):
        from .utils import str_to_list_for_stings
        extra_filters['eventType'] = str_to_list_for_stings(params.get('eventType'))

    size = params.get('size', 500)
    start = params.get('start', 0)
    order_by = params.get('orderBy', '')
    if order_by:
        parts = order_by.split(' ')
        order_by_field = parts[0] if len(parts) >= 1 else 'incidentLastSeen'
        descending = len(parts) > 1 and parts[1].upper() == 'DESC'
    else:
        order_by_field = 'incidentLastSeen'
        descending = True

    incidents = run_async(_get_incidents_async(
        config, time_from, time_to, status_codes, extra_filters,
        size, order_by_field, descending,
    ))
    return parseIncidents(incidents)


async def _get_incidents_async(
    config, time_from, time_to, status_codes, extra_filters,
    size, order_by, descending,
):
    """Async implementation of get_incidents using pyfortisiem."""
    from .connections import get_async_client
    async with get_async_client(config) as fsm:
        incidents = await fsm.list_incidents(
            time_from=time_from if time_from else None,
            time_to=time_to if time_to else None,
            status=status_codes or None,
            size=size,
            order_by=order_by,
            descending=descending,
            extra_filters=extra_filters or None,
        )
        return [_incident_to_dict(inc) for inc in incidents]


def get_incident_details(config, params):
    """Get details of specific incidents by ID -- uses pyfortisiem async client."""
    from .connections import get_async_client, run_async

    if not isinstance(params.get('incidentId'), list):
        params['incidentId'] = [params.get('incidentId')]

    time_from = convert_time_to_miliseconds(params.get('timeFrom'))
    time_to = convert_time_to_miliseconds(params.get('timeTo'))

    return run_async(_get_incident_details_async(
        config, params['incidentId'], time_from, time_to,
    ))


async def _get_incident_details_async(config, incident_ids, time_from, time_to):
    """Async implementation of get_incident_details."""
    from .connections import get_async_client
    async with get_async_client(config) as fsm:
        results = []
        for iid in incident_ids:
            inc = await fsm.get_incident(
                int(iid),
                time_from=time_from if time_from else None,
                time_to=time_to if time_to else None,
            )
            if inc is not None:
                results.append(_incident_to_dict(inc))
        return {"data": results}


def get_associated_events(config, params):
    """Get triggering events for an incident -- uses pyfortisiem async client."""
    from .connections import get_async_client, run_async

    incident_id = int(params.get('incident_id'))
    # info.json names this `per_page`; v1 (and older v2 playbooks) send
    # `perPage`. Reading only `perPage` silently ignored the designer's value.
    size = params.get('per_page') or params.get('perPage') or 10
    time_from = convert_time_to_miliseconds(params.get("timeFrom"))
    time_to = convert_time_to_miliseconds(params.get("timeTo"))

    return run_async(_get_associated_events_async(
        config, incident_id, size, time_from, time_to,
    ))


async def _get_associated_events_async(config, incident_id, size, time_from, time_to):
    """Async implementation of get_associated_events."""
    from .connections import get_async_client
    async with get_async_client(config) as fsm:
        events = await fsm.get_associated_events(
            incident_id, size=size,
            time_from=time_from if time_from else None,
            time_to=time_to if time_to else None,
        )
        return [_event_to_dict(ev) for ev in events]


def get_incident_with_events(config, params):
    """Get a single incident with its triggering events -- uses pyfortisiem.

    This is the marquee operation: fetches the incident and its events
    concurrently in one call.
    """
    from .connections import get_async_client, run_async

    incident_id = int(params.get('incident_id'))
    size = params.get('event_count', 10) or 10
    use_query_lifecycle = params.get('use_query_lifecycle', False)
    time_from = convert_time_to_miliseconds(params.get("timeFrom"))
    time_to = convert_time_to_miliseconds(params.get("timeTo"))

    result = run_async(_get_incident_with_events_async(
        config, incident_id, size, use_query_lifecycle, time_from, time_to,
    ))
    if result is None:
        return {"message": "Incident not found", "incident_id": incident_id}
    return result


async def _get_incident_with_events_async(
    config, incident_id, size, use_query_lifecycle, time_from, time_to,
):
    """Async implementation of get_incident_with_events."""
    from .connections import get_async_client
    async with get_async_client(config) as fsm:
        iwe = await fsm.get_incident_with_events(
            incident_id, size=size,
            use_query_lifecycle=use_query_lifecycle,
            time_from=time_from if time_from else None,
            time_to=time_to if time_to else None,
        )
        if iwe is None:
            return None
        return _incident_with_events_to_dict(iwe)


# ---------------------------------------------------------------------------
# Incident mutation operations (backward-compatible REST path)
# ---------------------------------------------------------------------------

def update_incident(config, params):
    try:
        params['incidentStatus'] = PARAMS_MAPPING.get(params.get('incidentStatus'))
        params['incidentId'] = str(params.get('incidentId'))
        params["resolution"] = PARAMS_MAPPING.get(params.get('resolution'), '')
        params_list = {k: str(v) for k, v in params.items() if v is not None and v != ''}
        return update_incident_data(config, params, params_list, 'Incident updated')
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def incident_comment(config, params):
    try:
        body = {
            "incidentId": str(params.get('id')),
            "comments": params.get('comment_text')
        }
        return update_incident_data(config, params, body, 'Successfully added comment to incident')
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def clear_incident(config, params):
    try:
        body = {
            "incidentId": str(params.get('id')),
            "incidentStatus": "2",
            "comments": params.get('comment_text')
        }
        return update_incident_data(config, params, body, 'Successfully cleared specified incident with reason')
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def update_incident_data(config, params, body, msg):
    try:
        fortisiem_obj = FortiSIEM(config)
        headers = fortisiem_obj.generate_headers()
        if params.get('id'):
            result = {'message': 'Provided incident does not exist', 'incident_id': params.get('id')}
        else:
            result = {'message': 'Provided incident does not exist', 'incident_id': params.get('incidentId')}
        endpoint = '/rest/incident/external?incident='
        res = fortisiem_obj.make_rest_call(endpoint, headers=headers, data=json.dumps(body), method='POST')
        if res == '"OK"':
            result['message'] = msg
        return result
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


# ---------------------------------------------------------------------------
# MCP operations (FortiSIEM 8.0+)
# ---------------------------------------------------------------------------

def get_incidents_by_entity(config, params):
    """MCP: Get active incidents touching one entity (IP/hostname/username)."""
    from pyfortisiem.models import EntityIncidentQuery, TimeUnit
    from .connections import get_mcp_session

    session, sync = get_mcp_session(config)
    try:
        q = EntityIncidentQuery(
            time_value=params.get('time_value', 24),
            time_unit=TimeUnit(params.get('time_unit', 'hours')),
            ip=params.get('ip'),
            hostname=params.get('hostname'),
            username=params.get('username'),
        )
        results = session.get_incidents_by_entity(q)
        return [_to_dict(r) for r in results]
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(str(err))
    finally:
        sync.close()


def get_related_incidents(config, params):
    """MCP: Get incidents sharing entities with the given one."""
    from .connections import get_mcp_session

    incident_id = int(params.get('incident_id'))
    session, sync = get_mcp_session(config)
    try:
        results = session.get_related_incidents_by_id(incident_id)
        return [_to_dict(r) for r in results]
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(str(err))
    finally:
        sync.close()


def get_trigger_events(config, params):
    """MCP: Get raw events that triggered an incident (columnar EventTable)."""
    from .connections import get_mcp_session

    incident_id = int(params.get('incident_id'))
    session, sync = get_mcp_session(config)
    try:
        table = session.get_trigger_events_by_incident_id(incident_id)
        return {"columns": table.columns, "records": table.records()}
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(str(err))
    finally:
        sync.close()


def get_entity_context(config, params):
    """MCP: Get unified entity context (ip/hostname/username)."""
    from pyfortisiem.models import EntityContextQuery
    from .connections import get_mcp_session

    session, sync = get_mcp_session(config)
    try:
        q = EntityContextQuery(
            ip=params.get('ip'),
            hostname=params.get('hostname'),
            username=params.get('username'),
        )
        ctx = session.get_context_by_entity(q)
        return _to_dict(ctx)
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(str(err))
    finally:
        sync.close()


def get_entity_reputation(config, params):
    """MCP: Get threat-feed reputation for IPs, URLs, domains, or hashes."""
    from pyfortisiem.models import EntityReputationQuery
    from .connections import get_mcp_session

    session, sync = get_mcp_session(config)
    try:
        ip_list = params.get('ip')
        url_list = params.get('url')
        domain_list = params.get('domain')
        hash_list = params.get('hash')

        q = EntityReputationQuery(
            ip=ip_list if isinstance(ip_list, list) else ([ip_list] if ip_list else None),
            url=url_list if isinstance(url_list, list) else ([url_list] if url_list else None),
            domain=domain_list if isinstance(domain_list, list) else ([domain_list] if domain_list else None),
            hash=hash_list if isinstance(hash_list, list) else ([hash_list] if hash_list else None),
        )
        results = session.get_reputation_by_entity(q)
        return [_to_dict(r) for r in results]
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(str(err))
    finally:
        sync.close()


def get_iocs_for_incidents(config, params):
    """MCP: Get IOCs across given incidents."""
    from .connections import get_mcp_session

    incident_ids = params.get('incident_ids')
    if not isinstance(incident_ids, list):
        incident_ids = [int(incident_ids)]
    else:
        incident_ids = [int(i) for i in incident_ids]

    session, sync = get_mcp_session(config)
    try:
        results = session.get_iocs_by_incident_ids(incident_ids)
        return [_to_dict(r) for r in results]
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(str(err))
    finally:
        sync.close()


def update_incident_severity(config, params):
    """MCP: Update incident severity (LOW/MEDIUM/HIGH)."""
    from pyfortisiem.models import IncidentUpdate, Severity
    from .connections import get_mcp_session

    session, sync = get_mcp_session(config)
    try:
        u = IncidentUpdate(
            incidentId=int(params.get('incident_id')),
            incidentSeverity=Severity(params.get('severity')),
        )
        ack = session.update_incident_severity_by_id(u)
        return _to_dict(ack)
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(str(err))
    finally:
        sync.close()


def update_incident_resolution(config, params):
    """MCP: Update incident resolution (TruePositive/FalsePositive)."""
    from pyfortisiem.models import IncidentUpdate, Resolution
    from .connections import get_mcp_session

    session, sync = get_mcp_session(config)
    try:
        u = IncidentUpdate(
            incidentId=int(params.get('incident_id')),
            incidentResolution=Resolution(params.get('resolution')),
        )
        ack = session.update_incident_resolution_by_id(u)
        return _to_dict(ack)
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(str(err))
    finally:
        sync.close()


def append_incident_comment_mcp(config, params):
    """MCP: Append a comment to an incident."""
    from pyfortisiem.models import IncidentUpdate
    from .connections import get_mcp_session

    session, sync = get_mcp_session(config)
    try:
        u = IncidentUpdate(
            incidentId=int(params.get('incident_id')),
            comments=params.get('comment'),
        )
        ack = session.append_incident_comment_by_id(u)
        return _to_dict(ack)
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(str(err))
    finally:
        sync.close()


def clear_incident_mcp(config, params):
    """MCP: Clear an incident by ID."""
    from .connections import get_mcp_session

    incident_id = int(params.get('incident_id'))
    session, sync = get_mcp_session(config)
    try:
        ack = session.clear_incident_by_id(incident_id)
        return _to_dict(ack)
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(str(err))
    finally:
        sync.close()


def get_top_risky_users(config, params):
    """MCP: Get top-10 users by risk score."""
    from .connections import get_mcp_session

    session, sync = get_mcp_session(config)
    try:
        results = session.top_10_risky_users()
        return [_to_dict(r) for r in results]
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(str(err))
    finally:
        sync.close()


def get_top_risky_devices(config, params):
    """MCP: Get top-10 devices by risk score."""
    from .connections import get_mcp_session

    session, sync = get_mcp_session(config)
    try:
        results = session.top_10_risky_devices()
        return [_to_dict(r) for r in results]
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(str(err))
    finally:
        sync.close()


def query_postgres(config, params):
    """MCP: Read-only Postgres query (CMDB/incidents/health)."""
    from .connections import get_mcp_session

    sql = params.get('sql')
    if not sql:
        raise ConnectorError("sql parameter is required")
    session, sync = get_mcp_session(config)
    try:
        results = session.query_postgres(sql)
        return results
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(str(err))
    finally:
        sync.close()


def query_clickhouse(config, params):
    """MCP: Read-only ClickHouse events query."""
    from .connections import get_mcp_session

    sql = params.get('sql')
    if not sql:
        raise ConnectorError("sql parameter is required")
    session, sync = get_mcp_session(config)
    try:
        table = session.query_clickhouse(sql)
        return {"columns": table.columns, "records": table.records()}
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(str(err))
    finally:
        sync.close()


def get_postgres_prompts(config, params):
    """MCP: Get SQL authoring guidance for Postgres."""
    from .connections import get_mcp_session

    session, sync = get_mcp_session(config)
    try:
        return session.query_postgres_prompts()
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(str(err))
    finally:
        sync.close()


def get_clickhouse_prompts(config, params):
    """MCP: Get SQL authoring guidance for ClickHouse."""
    from .connections import get_mcp_session

    session, sync = get_mcp_session(config)
    try:
        return session.query_clickhouse_prompts()
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(str(err))
    finally:
        sync.close()


# ---------------------------------------------------------------------------
# Credential management operations
# ---------------------------------------------------------------------------

def list_oauth_credentials(config, params):
    """List existing API-token credentials."""
    from .connections import get_sync_client

    sync = get_sync_client(config)
    try:
        sync.login()
        creds = sync.list_oauth_credentials()
        return [_normalize_credential(_to_dict(c)) for c in creds]
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(str(err))
    finally:
        sync.close()


def _normalize_credential(cred_dict):
    """Give an OAuth credential dict consistent snake_case key names.

    ``_to_dict`` serialises by alias, and on the underlying model ``client_id``
    carries the alias ``clientId`` while ``client_secret`` carries none -- so
    the raw result mixes conventions (``clientId`` + ``client_secret``) and a
    caller reaching for ``client_id`` silently gets nothing. Emit both spellings
    so either works.
    """
    if not isinstance(cred_dict, dict):
        return cred_dict
    if "client_id" not in cred_dict and "clientId" in cred_dict:
        cred_dict["client_id"] = cred_dict["clientId"]
    if "client_secret" not in cred_dict and "clientSecret" in cred_dict:
        cred_dict["client_secret"] = cred_dict["clientSecret"]
    return cred_dict


def create_oauth_credential(config, params):
    """Create an API-token credential.

    The ``client_secret`` is returned **only here**, at creation time -- it
    cannot be read back afterwards, so callers must persist it now.
    """
    from .connections import get_sync_client

    name = params.get('name')
    if not name:
        raise ConnectorError("name parameter is required")
    sync = get_sync_client(config)
    try:
        cred = sync.create_oauth_credential(name)
        return _normalize_credential(_to_dict(cred))
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(str(err))
    finally:
        sync.close()


def revoke_oauth_credential(config, params):
    """Revoke an API-token credential by its numeric id."""
    from .connections import get_sync_client

    cred_id = int(params.get('credential_id'))
    sync = get_sync_client(config)
    try:
        sync.login()
        sync.revoke_oauth_credential(cred_id)
        return {"message": "Credential revoked", "credential_id": cred_id}
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(str(err))
    finally:
        sync.close()


# ---------------------------------------------------------------------------
# Health check and version
# ---------------------------------------------------------------------------

def _check_health(config):
    """Health check -- uses pyfortisiem health() for speed, falls back to orgs."""
    try:
        from .connections import get_async_client, run_async
        return run_async(_check_health_async(config))
    except ImportError:
        list_data = get_monitored_organizations(config, {})
        if list_data:
            return True
    except Exception as err:
        raise ConnectorError('{0}'.format(err))


async def _check_health_async(config):
    """Async health check using pyfortisiem."""
    from .connections import get_async_client
    async with get_async_client(config) as fsm:
        status = await fsm.health()
        if status == 200:
            return True
        raise ConnectorError(f"FortiSIEM health check failed: HTTP {status}")


def get_fsm_version(config):
    try:
        fortisiem_obj = FortiSIEM(config)
        endpoint = "/rest/system/health/summary"
        headers = fortisiem_obj.generate_headers()
        headers.update({"Accept": "application/json", "Content-Type": "application/json"})
        version = ""
        res = fortisiem_obj.make_rest_call(endpoint, headers=headers, method="GET")
        instance_id = None
        for instance in res:
            if instance.get("name") == "Super":
                instance_id = instance.get("id")
                break
        if instance_id:
            endpoint = "/rest/system/health/instance"
            params = {"instanceId": instance_id}
            res = fortisiem_obj.make_rest_call(endpoint, headers=headers, params=params, method="GET")
            utils_obj = Utils(res)
            version = utils_obj.get_value_by_key("version")
        if version:
            version = version[0:5]
        else:
            raise ConnectorError("Version not received from FortiSIEM")
        logger.debug(f"Check health FortiSIEM version is: {version}")
        return version
    except Exception as err:
        logger.error(f"Check health FortiSIEM version fetching failed: {str(err)}")
        return ""


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def _to_dict(obj):
    """Convert a pydantic model to a dict (by_alias, all fields)."""
    if hasattr(obj, "model_dump"):
        return obj.model_dump(by_alias=True, exclude_none=False)
    if isinstance(obj, dict):
        return obj
    if isinstance(obj, list):
        return [_to_dict(item) for item in obj]
    return obj


def _incident_to_dict(incident):
    """Convert a pydantic Incident to a plain dict."""
    return _to_dict(incident)


def _event_to_dict(event):
    """Convert a pydantic Event to a plain dict."""
    return _to_dict(event)


def _incident_with_events_to_dict(iwe):
    """Convert an IncidentWithEvents to a plain dict with events list."""
    d = _to_dict(iwe)
    if isinstance(d, dict) and "events" in d:
        d["events"] = [_event_to_dict(ev) for ev in (iwe.events if hasattr(iwe, "events") else [])]
    return d


# ---------------------------------------------------------------------------
# parseIncidents (kept for backward compatibility with get_incidents output)
# ---------------------------------------------------------------------------

def parseIncidents(incidents):
    """Parse FortiSIEM incident list -- enriches status, src/target, MITRE."""
    if isinstance(incidents, dict) and "data" in incidents:
        incident_list = incidents["data"]
    else:
        incident_list = incidents
        incidents = {"data": incidents}

    for incident in incident_list:
        phIncidentCategory = incident.get('phIncidentCategory')
        incidentStatus = incident.get('incidentStatus')
        incidentStatusStr = INCIDENT_STATUS.get(incidentStatus)
        if incidentStatusStr is not None:
            incident['incidentStatusStr'] = incidentStatusStr

        incidentSrc = incident.get('incidentSrc')
        incidentTarget = incident.get('incidentTarget')
        attackTechnique = incident.get('attackTechnique')
        if incidentSrc is not None:
            incident = update_attr_data(incidentSrc, incident, key="incidentSrc")
        if incidentTarget is not None:
            incident = update_attr_data(incidentTarget, incident, key="incidentTarget")
        if attackTechnique is None:
            continue
        if 'techniqueid' in attackTechnique:
            jsonMitre = json.loads(attackTechnique)
            incident["attackTechnique"] = jsonMitre
    return {"data": incident_list}


# ---------------------------------------------------------------------------
# Operations registry
# ---------------------------------------------------------------------------

operations = {
    # Health
    'check_health': _check_health,

    # Incident operations (pyfortisiem-powered)
    'async_get_incidents_rest': async_get_incidents_rest,
    'get_incidents': get_incidents,
    'get_incident_details': get_incident_details,
    'get_incident_with_events': get_incident_with_events,
    'get_associated_events': get_associated_events,

    # Incident mutation (REST)
    'update_incident': update_incident,
    'incident_comment': incident_comment,
    'clear_incident': clear_incident,

    # Incident mutation (MCP)
    'update_incident_severity': update_incident_severity,
    'update_incident_resolution': update_incident_resolution,
    'append_incident_comment_mcp': append_incident_comment_mcp,
    'clear_incident_mcp': clear_incident_mcp,

    # MCP investigation tools
    'get_incidents_by_entity': get_incidents_by_entity,
    'get_related_incidents': get_related_incidents,
    'get_trigger_events': get_trigger_events,
    'get_entity_context': get_entity_context,
    'get_entity_reputation': get_entity_reputation,
    'get_iocs_for_incidents': get_iocs_for_incidents,
    'get_top_risky_users': get_top_risky_users,
    'get_top_risky_devices': get_top_risky_devices,

    # MCP SQL query tools
    'query_postgres': query_postgres,
    'query_clickhouse': query_clickhouse,
    'get_postgres_prompts': get_postgres_prompts,
    'get_clickhouse_prompts': get_clickhouse_prompts,

    # Credential management
    'list_oauth_credentials': list_oauth_credentials,
    'create_oauth_credential': create_oauth_credential,
    'revoke_oauth_credential': revoke_oauth_credential,

    # Native ingestion
    'ingest_incidents': ingest_incidents,

    # Legacy device/org operations (XML REST)
    'get_monitored_devices': get_monitored_devices,
    'get_devices_details': get_devices_details,
    'get_devices_details_in_address': get_devices_details,
    'get_device_info': get_device_info,
    'get_monitored_organizations': get_monitored_organizations,
    'get_org_name_by_org_id': get_org_name_by_org_id,

    # Legacy event operations (XML REST)
    'run_report': run_report,
    'get_event_details': get_event_details,
    'search_events': search_events,
    'get_incident_attributes': get_incident_attributes,
    'get_events_by_query_id': get_events_by_query_id,

    # Watch list operations (XML REST)
    'get_watch_lists': get_watch_lists,
    'add_watch_list_entries_to_watch_list_groups': add_watch_list_entries_to_watch_list_groups,
    'create_watchlist_group': create_watchlist_group,
    'update_watch_list_entry': update_watch_list_entry,
    'delete_watch_list_entry': delete_watch_list_entry,
    'delete_watch_list': delete_watch_list,
    'get_watch_list_entry': get_watch_list_entry,
    'get_watch_list_entries_count': get_watch_list_entries_count,

    # Lookup table operations (XML REST)
    'get_all_lookup_tables': get_all_lookup_tables,
    'create_lookup_table': create_lookup_table,
    'delete_lookup_table': delete_lookup_table,
    'import_lookup_table_data': import_lookup_table_data,
    'check_import_task_status': check_import_task_status,
    'get_lookup_table_data': get_lookup_table_data,
    'update_lookup_table_data': update_lookup_table_data,
    'delete_lookup_table_data': delete_lookup_table_data,

    # Context operations (REST, backward compat)
    'get_ip_context': get_ip_context,
    'get_host_context': get_host_context,
    'get_user_context': get_user_context,

    # Version
    'get_fsm_version': get_fsm_version,
}

# v1 (fortinet-fortisiem) operations v2 had dropped -- see v1_compat.py.
operations.update(V1_COMPAT_OPERATIONS)
