"""
Copyright start
Copyright (C) 2008 - 2024 FortinetInc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end
"""

import json
import codecs
from hashlib import sha1
from urllib.parse import quote, urlencode

from .connections import *
import random


def generate_salt_string(fsm_obj, headers):
    chars = []
    for i in range(RANGE):
        chars.append(random.choice(ALPHABET))
    url = "/rest/h5/sec/loginInfo?s={0}".format("".join(chars))
    payload = {"userName": fsm_obj.user, "organization": fsm_obj.organization}
    response = fsm_obj.make_rest_call(url, headers=headers, method='POST', data=json.dumps(payload))
    if isinstance(response, dict):
        salt = response.get('salt')
    else:
        salt = json.loads(response)["salt"]
    logger.debug('got the salted string from server')
    return salt


def login_fsm(fortisiem_obj):
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'Connection': 'keep-alive',
        'Content-Type': 'text/plain;charset=UTF-8'
    }
    salt = generate_salt_string(fortisiem_obj, headers)
    passwrd = ('{salt}{passwd}'.format(salt=salt, passwd=fortisiem_obj.password))
    sha1_val = (sha1(bytes(passwrd, "ascii")).hexdigest()).lower().upper()
    cred = {"username": fortisiem_obj.user, "password": sha1_val, "domain": fortisiem_obj.organization}
    url = '/rest/h5/sec/login?s={salt}'.format(salt=salt)
    response, cookies = fortisiem_obj.make_rest_call(url, headers=headers, method='POST', data=json.dumps(cred),
                                                     login_flag=True)
    if response == '"success"':
        cookies_dict = cookies.get_dict()
        s_encoded = codecs.encode((bytes(cookies_dict.get('s'), 'utf-8')), 'hex').decode('utf-8').upper()
        return s_encoded
    else:
        raise ConnectorError('failed to login to FortiSIEM server')


def logout_fsm(fortisiem_obj, s_encoded):
    endpoint = '/rest/h5/user/kickLockUser'
    params_dict = {
        'sessionId': fortisiem_obj.cookies_dict.get('JSESSIONID'),
        's': s_encoded
    }
    response = fortisiem_obj.make_rest_call(endpoint, method='POST', params=params_dict, resource_flag=True)
    return response
