import argparse
import http.client
import re
import socket
import ssl
import sys
from urllib.parse import urlparse
from typing import Tuple, List

import utils
from constants import DEFAULT_URL_SCHEME, EVAL_WARN


class SecurityHeadersException(Exception):
    pass


class InvalidTargetURL(SecurityHeadersException):
    pass


class UnableToConnect(SecurityHeadersException):
    pass

class ExceedMaxRedirection(SecurityHeadersException):
    pass

class SecurityHeaders():
    DEFAULT_TIMEOUT = 10

    # Let's try to imitate a legit browser to avoid being blocked / flagged as web crawler
    REQUEST_HEADERS = {
        'Accept': ('text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,'
                   'application/signed-exchange;v=b3;q=0.9'),
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-GB,en;q=0.9',
        'Cache-Control': 'max-age=0',
        'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
                       'Chrome/106.0.0.0 Safari/537.36'),
    }

    SECURITY_HEADERS_DICT = {
        'x-frame-options': {
            'recommended': True,
            'eval_func': utils.eval_x_frame_options,
        },
        'strict-transport-security': {
            'recommended': True,
            'eval_func': utils.eval_sts,
        },
        'content-security-policy': {
            'recommended': True,
            'eval_func': utils.eval_csp,
        },
        'x-content-type-options': {
            'recommended': True,
            'eval_func': utils.eval_content_type_options,
        },
        'x-xss-protection': {
            # X-XSS-Protection is deprecated; not supported anymore, and may be even dangerous in older browsers
            'recommended': False,
            'eval_func': utils.eval_x_xss_protection,
        },
        'referrer-policy': {
            'recommended': True,
            'eval_func': utils.eval_referrer_policy,
        },
        'permissions-policy': {
            'recommended': True,
            'eval_func': utils.eval_permissions_policy,
        },
        'feature-policy':{ # old permission-policy
            'recommended': True,
            'eval_func': utils.eval_permissions_policy,
        },
    }

    SERVER_VERSION_HEADERS = [
        'x-powered-by',
        'server',
        'x-aspnet-version',
    ]

    def __init__(self, url, max_redirects=2, check_certificate=True, check_server_version_header=True):
        url, parsed = SecurityHeaders.parsed_url(url)
        self.check_server_version_header = check_server_version_header
        self.protocol_scheme = parsed.scheme
        self.hostname = parsed.hostname
        self.path = parsed.path
        self.max_redirects = max_redirects
        self.target_url = None
        self.verify_ssl = check_certificate
        self.headers = None
        self.port = parsed.port

        if self.max_redirects:
            self.target_url = self._follow_redirect_until_response(url, self.max_redirects)
        else:
            self.target_url = parsed

    def parsed_url(url):
        if "//" not in url:
            url = "//" + url # in order to make the url parse function work for google.com
        parsed = urlparse(url) # url = google.com:8443, parsed.scheme = google.com
        if not parsed.scheme:
            https_url = f"{DEFAULT_URL_SCHEME}://{parsed.netloc}{parsed.path}"
            parsed = urlparse(https_url)
            if not parsed.scheme and not parsed.netloc:
                raise InvalidTargetURL("Unable to parse the URL")
            
            https_check = SecurityHeaders.test_https(parsed.netloc)
            if https_check["supported"]:
                url = f"{DEFAULT_URL_SCHEME}://{parsed.netloc}{parsed.path}"
            else:
                url = f"http://{parsed.netloc}{parsed.path}"
            parsed = urlparse(url)
        return url,parsed

    def test_https(hostname):
        conn = http.client.HTTPSConnection(hostname, context=ssl.create_default_context(),
                                           timeout=SecurityHeaders.DEFAULT_TIMEOUT)
        try:
            conn.request('GET', '/')
        except (socket.gaierror, socket.timeout, ConnectionRefusedError):
            return {'supported': False, 'certvalid': False}
        except ssl.SSLError:
            return {'supported': True, 'certvalid': False}

        return {'supported': True, 'certvalid': True}

    def _follow_redirect_until_response(self, url, follow_redirects=5):
        _, temp_url = SecurityHeaders.parsed_url(url)
        while follow_redirects >= 0:
            if not temp_url.netloc:
                raise InvalidTargetURL(f"Invalid redirect URL: {temp_url}")

            conn = self.open_connection(temp_url)
            try:
                conn.request('GET', temp_url.path, headers=self.REQUEST_HEADERS)
                res = conn.getresponse()
            except (socket.gaierror, socket.timeout, ConnectionRefusedError, http.client.RemoteDisconnected) as e:
                raise UnableToConnect("Connection failed {}".format(temp_url.netloc)) from e
            except ssl.SSLError as e:
                raise UnableToConnect(f"SSL Error {e.reason}") from e
            except Exception as e:
                raise UnableToConnect(f"Unknown error {e}. Connection failed {temp_url.netloc}") from e

            if res.status >= 300 and res.status < 400:
                headers = res.getheaders()
                headers_dict = {x[0].lower(): x[1] for x in headers}
                if 'location' in headers_dict:
                    if re.match("^https?://", headers_dict['location']):
                        temp_url = urlparse(headers_dict['location'])
                    else:  # Probably relative path
                        temp_url = temp_url._replace(path=headers_dict['location'])
            else:
                return temp_url

            follow_redirects -= 1

        # More than x redirects, stop here
        raise ExceedMaxRedirection("Exceeded maximum number of redirects")


    def test_http_to_https(self, follow_redirects=5):
        url = "http://{}{}".format(self.hostname, self.path)
        target_url = self._follow_redirect_until_response(url)
        if target_url and target_url.scheme == 'https':
            return True

        return False

    def open_connection(self, target_url):
        if target_url.scheme == 'http':
            conn = http.client.HTTPConnection(target_url.netloc, timeout=self.DEFAULT_TIMEOUT)
        elif target_url.scheme == 'https':
            ctx = ssl.create_default_context()
            if not self.verify_ssl:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(target_url.netloc, context=ctx, timeout=self.DEFAULT_TIMEOUT)
        else:
            raise InvalidTargetURL("Unsupported protocol scheme")

        return conn

    def fetch_headers(self):
        """ Fetch headers from the target site and store them into the class instance """

        conn = self.open_connection(self.target_url)
        try:
            conn.request('GET', self.target_url.path, headers=self.REQUEST_HEADERS)
            res = conn.getresponse()
        except (socket.gaierror, socket.timeout, ConnectionRefusedError, ssl.SSLError, http.client.RemoteDisconnected) as e:
            raise UnableToConnect("Connection failed {}".format(self.target_url.hostname)) from e
        except Exception as e:
            raise UnableToConnect(f"Unknown error {e}. Connection failed {self.target_url.hostname}") from e

        headers = res.getheaders()
        self.headers = {x[0].lower(): x[1] for x in headers}
        self.get_duplicate_header(headers)
        
    def get_duplicate_header(self, raw_headers: List[Tuple[str, str]]):
        seen = set()
        duplicates = []
        for header, _ in raw_headers:
            header = header.lower()
            if header in seen:
                duplicates.append(header)
            seen.add(header)
        self.duplicated_headers = duplicates

    def check_headers(self):
        """ Default return array """
        retval = {}

        if not self.headers:
            raise SecurityHeadersException("Headers not fetched successfully")

        """ Loop through headers and evaluate the risk """
        for header in self.SECURITY_HEADERS_DICT:
            # check if security headers are duplicated
            if header in self.duplicated_headers:
                retval[header] = {
                    'defined': True,
                    'warn': True,
                    'contents': "",
                    'notes': "duplicated header",
                }
                continue
            
            if header in self.headers:
                eval_func = self.SECURITY_HEADERS_DICT[header].get('eval_func')
                if not eval_func:
                    raise SecurityHeadersException("No evaluation function found for header: {}".format(header))
                res, notes = eval_func(self.headers[header])
                retval[header] = {
                    'defined': True,
                    'warn': res == EVAL_WARN,
                    'contents': self.headers[header],
                    'notes': notes,
                }

            else:
                warn = self.SECURITY_HEADERS_DICT[header].get('recommended')
                retval[header] = {'defined': False, 'warn': warn, 'contents': None, 'notes': []}

        if self.check_server_version_header:
            for header in self.SERVER_VERSION_HEADERS:
                if header in self.headers:
                    res, notes = utils.eval_version_info(self.headers[header])
                    retval[header] = {
                        'defined': True,
                        'warn': res == EVAL_WARN,
                        'contents': self.headers[header],
                        'notes': notes,
                    }

        return retval


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check HTTP security headers',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('url', metavar='URL', type=str, help='Target URL')
    parser.add_argument('--max-redirects', dest='max_redirects', metavar='N', default=2, type=int,
                        help='Max redirects, set 0 to disable')
    parser.add_argument('--no-check-certificate', dest='no_check_certificate', action='store_true',
                        help='Do not verify TLS certificate chain')
    args = parser.parse_args()
    try:
        header_check = SecurityHeaders(args.url, args.max_redirects, args.no_check_certificate)
        header_check.fetch_headers()
        headers = header_check.check_headers()
    except SecurityHeadersException as e:
        print(e)
        sys.exit(1)

    if not headers:
        print("Failed to fetch headers, exiting...")
        sys.exit(1)

    for header, value in headers.items():
        if value['warn']:
            if not value['defined']:
                utils.print_warning("Header '{}' is missing".format(header))
            else:
                utils.print_warning("Header '{}' contains value '{}".format(header, value['contents']))
                for n in value['notes']:
                    print(" * {}".format(n))
        else:
            if not value['defined']:
                utils.print_ok("Header '{}' is missing".format(header))
            else:
                utils.print_ok("Header '{}' contains value".format(header))

    https = header_check.test_https()
    if https['supported']:
        utils.print_ok("HTTPS supported")
    else:
        utils.print_warning("HTTPS supported")

    if https['certvalid']:
        utils.print_ok("HTTPS valid certificate")
    else:
        utils.print_warning("HTTPS valid certificate")

    if header_check.test_http_to_https():
        utils.print_ok("HTTP -> HTTPS redirect")
    else:
        utils.print_warning("HTTP -> HTTPS redirect")
