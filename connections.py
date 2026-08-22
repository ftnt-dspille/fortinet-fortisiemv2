"""
Copyright start
Copyright (C) 2008 - 2024 FortinetInc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end
"""

import asyncio
import base64
import json
import time

import aiohttp
import requests

from .utils import *

MAX_RETRIES = 3
BACKOFF_FACTOR = 0.5

# FortiSIEM rejects the 11th concurrent server-side query from one source IP
# with a 429. Sitting at exactly 10 leaves no headroom: any other client -- or
# this connector's own scheduled ingestion -- pushes us over, and the retry
# budget (3 attempts, ~3s of linear backoff, no jitter) is too small for the
# query slots to drain. Stay below the cap instead of racing it.
MAX_CONCURRENT_REQUESTS = 6

try:
    from pyfortisiem import AsyncFortiSIEMClient, FortiSIEMClient, FortiSIEMError
    from pyfortisiem.models import Incident, Event, IncidentWithEvents
    _PYFORTISIEM = True
except ImportError:
    _PYFORTISIEM = False


def get_async_client(config):
    """Build an AsyncFortiSIEMClient from the connector config dict.

    Supports two auth modes (selected by the ``auth_mode`` config field):
    * ``Basic Auth``  -- username/password/org (backward compatible)
    * ``API Key``     -- OAuth2 client_credentials bearer (for MCP + REST)

    Returns an AsyncFortiSIEMClient that is NOT yet entered -- the caller is
    responsible for ``async with`` / ``aclose()``.
    """
    if not _PYFORTISIEM:
        raise ConnectorError("pyfortisiem is required for async operations")

    host = _normalize_host(config["server"])
    auth_mode = config.get("auth_mode", "Basic Auth")
    verify = config.get("verify_ssl", True)
    max_conc = config.get("max_concurrency", MAX_CONCURRENT_REQUESTS)

    if auth_mode == "API Key (OAuth2)":
        client_id = config.get("client_id")
        client_secret = config.get("client_secret")
        if not client_id or not client_secret:
            raise ConnectorError("API Key auth requires client_id and client_secret")
        return AsyncFortiSIEMClient.with_api_key(
            host, client_id, client_secret,
            verify=verify, max_concurrency=max_conc,
        )
    username = config["username"]
    password = config["password"]
    domain = config.get("organization", "Super")
    return AsyncFortiSIEMClient.with_basic_auth(
        host, username, password, domain=domain,
        verify=verify, max_concurrency=max_conc,
    )


def get_sync_client(config):
    """Build a sync FortiSIEMClient for MCP / credential management.

    Uses basic auth credentials; the caller can ``login()`` for h5 session
    or ``mint_token()`` for OAuth bearer as needed.
    """
    if not _PYFORTISIEM:
        raise ConnectorError("pyfortisiem is required for sync operations")

    host = _normalize_host(config["server"])
    username = config["username"]
    password = config["password"]
    domain = config.get("organization", "Super")
    verify = config.get("verify_ssl", True)
    return FortiSIEMClient(host, username, password, domain=domain, verify=verify)


# Bearer tokens, keyed by (host, client_id) -> (token, expires_at_epoch).
#
# A FortiSIEM OAuth credential issues a token exactly ONCE: the second
# client_credentials exchange for the same credential returns
# "400 Invalid input parameters". Minting per call therefore breaks every MCP
# operation after the first. Tokens are valid for `expiresIn` minutes (1440 by
# default), so cache and reuse until close to expiry.
_TOKEN_CACHE = {}

# Re-mint this long before the token actually expires, so a long-running
# operation cannot have it lapse mid-flight.
TOKEN_REFRESH_MARGIN_SECONDS = 300

# Matches the credential's documented `expiresIn` (minutes). Used only as a
# fallback when the token carries no readable expiry.
DEFAULT_TOKEN_TTL_SECONDS = 1440 * 60


def _token_expiry(token, default_ttl=DEFAULT_TOKEN_TTL_SECONDS):
    """Best-effort read of a JWT's `exp` claim, falling back to a fixed TTL."""
    try:
        payload = token.split('.')[1]
        payload += '=' * (-len(payload) % 4)  # restore base64url padding
        exp = json.loads(base64.urlsafe_b64decode(payload)).get('exp')
        if exp:
            return float(exp)
    except Exception:
        pass
    return time.time() + default_ttl


def get_mcp_session(config):
    """Build an MCP session for FortiSIEM 8.0+ tools.

    If the config has ``client_id`` / ``client_secret``, reuse (or mint) a
    bearer token for it. Otherwise fall back to basic-auth login → create
    credential → mint token (the full h5 flow handled by FortiSIEMClient).
    """
    if not _PYFORTISIEM:
        raise ConnectorError("pyfortisiem is required for MCP operations")

    sync = get_sync_client(config)
    client_id = config.get("client_id")
    client_secret = config.get("client_secret")

    if client_id and client_secret:
        cache_key = (_normalize_host(config["server"]), client_id)
        cached = _TOKEN_CACHE.get(cache_key)
        if cached and cached[1] - TOKEN_REFRESH_MARGIN_SECONDS > time.time():
            token = cached[0]
        else:
            # Only reachable on first use or once the token has aged out; a
            # credential that has already issued its one token cannot re-issue,
            # so a 400 here means the credential needs replacing.
            token = sync.mint_token(client_id, client_secret)
            _TOKEN_CACHE[cache_key] = (token, _token_expiry(token))
    else:
        # No credential configured. Cache per host so repeated calls reuse the
        # auto-created credential instead of leaving a new one on the appliance
        # every time an MCP operation runs.
        cache_key = (_normalize_host(config["server"]), "__auto__")
        cached = _TOKEN_CACHE.get(cache_key)
        if cached and cached[1] - TOKEN_REFRESH_MARGIN_SECONDS > time.time():
            token = cached[0]
        else:
            sync.login()
            cred = sync.create_oauth_credential("fortisoar_mcp_auto")
            token = sync.mint_token(cred.client_id, cred.client_secret)
            _TOKEN_CACHE[cache_key] = (token, _token_expiry(token))

    return sync.mcp_session(token), sync


def _normalize_host(server):
    """Strip protocol and trailing slash; pyfortisiem expects ``host:port``."""
    host = server.strip().rstrip("/")
    if host.startswith("https://"):
        host = host[len("https://"):]
    elif host.startswith("http://"):
        host = host[len("http://"):]
    return host


def run_async(coro):
    """Run an async coroutine to completion, handling the event loop lifecycle.

    Uses ``asyncio.run`` (Python 3.7+) which creates a fresh event loop,
    runs the coroutine, and closes the loop cleanly -- avoiding the deprecated
    ``asyncio.new_event_loop()`` / ``set_event_loop()`` anti-pattern.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result()
    except RuntimeError:
        pass
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Backward-compatible FortiSIEM class
#
# The original connector's operations all instantiate ``FortiSIEM(config)``
# and call ``make_rest_call`` / ``make_json_rest_call`` / ``async_make_rest_call``.
# We keep this class for backward compatibility with watch-list, lookup-table,
# and XML-based operations that are not covered by pyfortisiem.
# ---------------------------------------------------------------------------


def _decode_body(response, response_content):
    """Best-effort decode of an error response body.

    FortiSIEM sometimes sends a plain-text body under a JSON Content-Type, so
    fall back to the decoded text rather than letting the JSON parse error
    replace the actual error message.
    """
    try:
        return response.json()
    except Exception:
        return response_content


class FortiSIEM:
    def __init__(self, config):
        self.base_url = config.get('server').strip('/') + '/phoenix'
        if not self.base_url.startswith('https://') and not self.base_url.startswith('http://'):
            self.base_url = 'https://{0}'.format(self.base_url)
        self.organization = str(config['organization'])
        self.user = str(config['username'])
        self.username = self.organization + '/' + self.user
        self.password = str(config['password'])
        self.verify_ssl = config['verify_ssl']
        self.cookies_dict = {}
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

        self.error_msg = {
            400: 'The parameters are invalid.',
            401: 'Invalid credentials were provided Or Request Not authorized',
            403: 'Access Denied',
            404: 'The requested resource was not found',
            422: 'Parameters are missing in query/request body.',
            423: 'The parameters are invalid in path/query/request body.',
            500: 'Internal Server Error',
            503: 'Service Unavailable',
            'time_out': 'The request timed out while trying to connect to the remote server',
            'ssl_error': 'SSL certificate validation failed'}

    def get_headers(self, headers, resource_flag):
        if headers is None:
            if resource_flag:
                headers = {
                    "Accept": "application/json, text/plain, */*",
                    "Content-Type": "application/json;charset=UTF-8",
                    "Cookie": f"JSESSIONID={self.cookies_dict.get('JSESSIONID')}; s={self.cookies_dict.get('s')}"
                }
            else:
                headers = self.generate_headers()
        return headers

    async def async_make_rest_call(
            self,
            endpoint,
            params=None,
            headers=None,
            json_data=None,
            data=None,
            cookies=None,
            method="GET",
    ):
        url = f"{self.base_url}{endpoint}"
        logger.info("Request URL %s", url)

        if headers is None:
            headers = self.generate_headers()

        for attempt in range(MAX_RETRIES):
            async with self.semaphore:
                try:
                    async with aiohttp.ClientSession(
                            connector=aiohttp.TCPConnector(ssl=self.verify_ssl)
                    ) as session:
                        async with session.request(method, url, headers=headers, params=params, json=json_data,
                                                   data=data, cookies=cookies) as response:
                            if response.status == 200:
                                try:
                                    data = await response.json(content_type=None)
                                except aiohttp.ContentTypeError:
                                    data = await response.text()
                                    logger.error("Expected JSON response but got text: %s", data)
                                    raise ConnectorError(f"Expected JSON response but got text: {data}")
                            else:
                                data = await response.text()
                                logger.error("HTTP error %d: %s", response.status, data)
                                response.raise_for_status()

                        if response.ok:
                            return data
                        else:
                            logger.error("HTTP error %d: %s", response.status, data)
                            response.raise_for_status()

                except aiohttp.ClientResponseError as e:
                    if response.status == 429:
                        logger.warning("Rate limit exceeded. Retrying in %s seconds...",
                                       (attempt + 1) * BACKOFF_FACTOR)
                        await asyncio.sleep((attempt + 1) * BACKOFF_FACTOR)
                        continue
                    elif response.status == 400:
                        try:
                            data = await response.json(content_type=None)
                            return data
                        except Exception as e:
                            raise ConnectorError(f"Client error: {e}")
                    else:
                        logger.exception("Client error: %s", e)
                        raise ConnectorError(f"Client error: {e}")
                except aiohttp.ClientError as e:
                    logger.exception("Client error: %s", e)
                    raise ConnectorError(f"Client error: {e}")
                except Exception as e:
                    logger.exception("Unexpected error: %s", e)
                    raise ConnectorError(f"Unexpected error: {e}")

        raise ConnectorError(f"Failed to complete request after {MAX_RETRIES} attempts")

    def make_json_rest_call(self, endpoint, params=None, headers=None, json_data=None, data=None, cookies=None,
                            method='GET', files=None, login_flag=False, resource_flag=False):
        url = '{0}{1}'.format(self.base_url, endpoint)
        try:
            headers = self.get_headers(headers, resource_flag)
            logger.debug(
                f"\n----------------req start----------------\n{method} {url} \nparams: {params} \ndata: {data} \nheaders: {headers}\n")
            response = requests.request(method,
                                        url,
                                        data=data,
                                        headers=headers,
                                        verify=self.verify_ssl,
                                        params=params,
                                        files=files
                                        )

            logger.debug(
                f"\nres_status:{response.status_code} response: {response.json()} \n----------------req end----------------\n")

            if response.ok:
                logger.info('FortiSIEM successfully retrieved page: {0}'.format(response.url))
                return response.status_code, response.json()
            elif response.status_code in [400, 404, 429, 503]:
                logger.error(
                    'Status Code: {0}, Query URL: {1} Response Data: {2}'.format(response.status_code, response.url,
                                                                                 response.json()))
                logger.error(
                    'FortiSIEM may sometimes return a 404 in older versions, in place of a 429 or 503, indicating that more time is needed for the server to be ready to serve more pages. Connector will retry the page after a short wait')
                return response.status_code, response.json()
            else:
                logger.error('{0}'.format(response.content))
                raise ConnectorError('status code: {0}, error: {1}'.format(response.status_code, response.json()))
        except requests.exceptions.SSLError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(self.error_msg['ssl_error']))
        except requests.exceptions.ConnectionError as e:
            logger.exception('{0}'.format(e))
        except Exception as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(e))

    def make_rest_call(self, endpoint, params=None, headers=None, json_data=None, data=None, cookies=None,
                       method='GET', files=None, login_flag=False, resource_flag=False):

        url = '{0}{1}'.format(self.base_url, endpoint)
        try:
            headers = self.get_headers(headers, resource_flag)
            logger.debug(
                f"\n----------------req start----------------\n{method} {url} \nparams: {params} \ndata: {data} \nheaders: {headers}\n")
            response = requests.request(method,
                                        url,
                                        data=data,
                                        headers=headers,
                                        verify=self.verify_ssl,
                                        params=params,
                                        files=files
                                        )

            response_content = response.content.decode('utf-8')
            logger.debug(
                f"\nres_status:{response.status_code} response: {response_content} \n----------------req end----------------\n")
            if 'error code="255"' in response_content:
                json_resp = xmltodict.parse(response_content)
                error_msg = json_resp.get("response", {}).get("error", {}).get("description") or \
                            json_resp.get("response", {}).get("result", {}).get("error", {}).get("description")
                logger.error(error_msg)
                raise ConnectorError('Error : {0}'.format(error_msg))
            elif response.ok:
                if login_flag:
                    self.cookies_dict = response.cookies.get_dict()
                    return response_content, response.cookies
                # A bodyless success (204 from DELETE, say) carries no
                # Content-Type at all, so default to '' -- `in None` is a
                # TypeError, and it used to surface as a bogus connector error
                # on calls that had actually succeeded.
                elif 'json' in (response.headers.get('Content-Type') or ''):
                    try:
                        resp = response.json()
                    except Exception:
                        resp = response_content
                    return resp
                elif response.text == "":
                    return response
                return response_content
            elif response.status_code == 400 and 'json' in (response.headers.get('Content-Type') or ''):
                # Some endpoints label a plain-text error body as JSON (a 400
                # from the lookupTable data API answers 'Cannot find.'), so
                # decode defensively -- response.json() would raise
                # JSONDecodeError and bury the real error under a parse failure.
                detail = _decode_body(response, response_content)
                logger.error('{0}'.format(detail))
                raise ConnectorError(detail)
            elif response.status_code in [404, 503]:
                detail = _decode_body(response, response_content)
                logger.error('{0}'.format(detail))
                return detail
            elif response.status_code == 500:
                logger.error('{0}'.format(response.content))
                raise ConnectorError('{0}'.format(self.error_msg[response.status_code]))
            elif self.error_msg.get(response.status_code, None):
                logger.error('{0}'.format(response.content))
                raise ConnectorError(
                    'status code: {0}, error: {1}'.format(response.status_code, self.error_msg[response.status_code]))
            raise ConnectorError('status code: {0}, error: {1}'.format(response.status_code, response.content))
        except requests.exceptions.SSLError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(self.error_msg['ssl_error']))
        except requests.exceptions.ConnectionError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(self.error_msg['time_out']))
        except Exception as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(e))

    def generate_headers(self):
        try:
            auth = base64.b64encode((self.username + ":" + self.password).encode())
            return {'Authorization': 'Basic {0}'.format(auth.decode())}
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)
