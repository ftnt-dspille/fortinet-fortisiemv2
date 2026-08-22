"""
Copyright start
Copyright (C) 2008 - 2024 FortinetInc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end
"""

ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

RANGE = 16

resource_dict ={
    'Malware IP': 'ip',
    'Malware Domains': 'site',
    'Malware Urls': 'url',
    'Malware Hash': 'hash',
    'Malware Processes': 'proc'
}


PARAMS_MAPPING = {
    "Active": "0",
    "Auto Cleared": "1",
    "Manually Cleared": "2",
    "System Cleared": "3",
    "True Positive": "2",
    "False Positive": "3"
}


INCIDENT_CATEGORY_MAPPING = {"Availability": 1, "Performance": 2, "Change": 3, "Security": 4, "Other": 5}


get_incident_param_list = {
    'reportingDevice': 'incidentRptDevName',
    'incidentCategory': 'phIncidentCategory',
    'incidentSubCategory': 'phSubIncidentCategory',
    'resolution': 'incidentReso',
    'eventType': 'eventType'

}
incident_query_map = {
    'active': 'incidentStatus = 0 OR ',
    'auto cleared': 'incidentStatus = 1 OR ',
    'manually cleared': 'incidentStatus = 2 OR ',
    'system cleared': 'incidentStatus = 3 OR ',
    'high': 'eventSeverityCat = "HIGH" OR ',
    'medium': 'eventSeverityCat = "MEDIUM" OR ',
    'low': 'eventSeverityCat = "LOW" OR '
}

event_mapping = {
    "1-Deny": "1",
    "0-Permit": "0"
}

time_map = {
    'Minutes': 1,
    'Hours': 60,
    'Days': 24 * 60
}


tmp_endpoints = {
    "Get All Watch Lists": "/rest/watchlist/all",
    "By Watch List ID": "/rest/watchlist/{watch_list_id}",
    "By Watch List Entry Value": "/rest/watchlist/value",
    "By Watch List Entry ID": "/rest/watchlist/byEntry/{watch_list_entry_id}"
}

watch_list_fields = {
    "State": "active",
    "Last Seen": "lastseen",
    "Count": "count"
}


INCIDENT_STATUS = {
    0: "active",
    1: "automatically cleared",
    2: "manually cleared",
    3: "system cleared"
}
