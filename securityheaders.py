import argparse
import http.client
import socket
import ssl
import sys
from urllib.parse import urlparse

import utils
from constants import EVAL_WARN, DEFAULT_URL_SCHEME


class SecurityHeadersException(Exception):
    pass


class InvalidTargetURL(SecurityHeadersException):
    pass


class UnableToConnect(SecurityHeadersException):
    pass


class SecurityHeaders():
    HEADERS_DICT = {
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
        'server': {
            'recommended': False,
            'eval_func': utils.eval_version_info,
        },
        'x-powered-by': {
            'recommended': False,
            'eval_func': utils.eval_version_info,
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
        }
    }

    def __init__(self, url, max_redirects=2):
        parsed = urlparse(url)
        if not parsed.scheme and not parsed.netloc:
            url = "{}://{}".format(DEFAULT_URL_SCHEME, url)
            parsed = urlparse(url)
            if not parsed.scheme and not parsed.netloc:
                raise InvalidTargetURL("Unable to parse the URL")

        self.protocol_scheme = parsed.scheme
        self.hostname = parsed.netloc
        self.path = parsed.path
        self.max_redirects = max_redirects
        self.headers = None

    def test_https(self):
        conn = http.client.HTTPSConnection(self.hostname, context=ssl.create_default_context(), timeout=10)
        try:
            conn.request('GET', '/')
        except (socket.gaierror, socket.timeout, ConnectionRefusedError):
            return {'supported': False, 'certvalid': False}
        except ssl.SSLError:
            return {'supported': True, 'certvalid': False}

        return {'supported': True, 'certvalid': True}

    def _follow_redirect_until_response(self, url, follow_redirects=5):
        temp_url = urlparse(url)
        while follow_redirects >= 0:
            sslerror = False
            if not temp_url.netloc:
                raise InvalidTargetURL("Invalid redirect URL")

            if temp_url.scheme == 'http':
                conn = http.client.HTTPConnection(temp_url.netloc, timeout=10)
            elif temp_url.scheme == 'https':
                ctx = ssl._create_stdlib_context()
                conn = http.client.HTTPSConnection(temp_url.netloc, context=ctx, timeout=10)
            else:
                raise InvalidTargetURL("Unsupported protocol scheme")

            try:
                conn.request('HEAD', temp_url.path)
                res = conn.getresponse()
                if temp_url.scheme == 'https':
                    sslerror = False
            except (socket.gaierror, socket.timeout, ConnectionRefusedError) as e:
                raise UnableToConnect("Connection failed {}".format(temp_url.netloc)) from e
            except ssl.SSLError:
                sslerror = True

            # If SSL error, retry without verifying the certificate chain
            if sslerror:
                conn = http.client.HTTPSConnection(temp_url.netloc, timeout=10, context=ssl._create_stdlib_context())
                try:
                    conn.request('HEAD', temp_url.path)
                    res = conn.getresponse()
                except (socket.gaierror, socket.timeout, ConnectionRefusedError, ssl.SSLError) as e:
                    raise UnableToConnect("Connection failed {}".format(temp_url.netloc)) from e

            if res.status >= 300 and res.status < 400:
                headers = res.getheaders()
                headers_dict = {x[0].lower(): x[1] for x in headers}
                if 'location' in headers_dict:
                    temp_url = urlparse(headers_dict['location'])
            else:
                return temp_url

            follow_redirects -= 1

        # More than x redirects, stop here
        return None

    def test_http_to_https(self, follow_redirects=5):
        url = "http://{}{}".format(self.hostname, self.path)
        target_url = self._follow_redirect_until_response(url)
        if target_url and target_url.scheme == 'https':
            return True

        return False

    def fetch_headers(self):
        """ Fetch headers from the target site and store them into the class instance """
        initial_url = "{}://{}{}".format(self.protocol_scheme, self.hostname, self.path)
        target_url = None
        if self.max_redirects:
            target_url = self._follow_redirect_until_response(initial_url, self.max_redirects)

        if not target_url:
            # If redirects lead to failing URL, fall back to the initial url
            target_url = urlparse(initial_url)

        if target_url.scheme == 'http':
            conn = http.client.HTTPConnection(target_url.hostname, timeout=10)
        elif target_url.scheme == 'https':
            # Don't verify certs here - we're interested in headers, HTTPS is checked separately
            ctx = ssl._create_stdlib_context()
            conn = http.client.HTTPSConnection(target_url.hostname, context=ctx, timeout=10)
        else:
            raise InvalidTargetURL("Unsupported protocol scheme")

        try:
            conn.request('HEAD', target_url.path)
            res = conn.getresponse()
        except (socket.gaierror, socket.timeout, ConnectionRefusedError, ssl.SSLError) as e:
            raise UnableToConnect("Connection failed {}".format(target_url.hostname)) from e

        headers = res.getheaders()
        self.headers = {x[0].lower(): x[1] for x in headers}

    def check_headers(self):
        """ Default return array """
        retval = {}

        if not self.headers:
            raise SecurityHeadersException("Headers not fetched successfully")

        """ Loop through headers and evaluate the risk """
        for header in self.HEADERS_DICT:
            if header in self.headers:
                eval_func = self.HEADERS_DICT[header].get('eval_func')
                if not eval_func:
                    raise SecurityHeadersException("No evaluation function found for header: {}".format(header))
                warn = eval_func(self.headers[header]) == EVAL_WARN
                retval[header] = {'defined': True, 'warn': warn, 'contents': self.headers[header]}
            else:
                warn = self.HEADERS_DICT[header].get('recommended')
                retval[header] = {'defined': False, 'warn': warn, 'contents': None}

        return retval


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check HTTP security headers',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('url', metavar='URL', type=str, help='Target URL')
    parser.add_argument('--max-redirects', dest='max_redirects', metavar='N', default=2, type=int,
                        help='Max redirects, set 0 to disable')
    args = parser.parse_args()
    header_check = SecurityHeaders(args.url, args.max_redirects)
    header_check.fetch_headers()
    headers = header_check.check_headers()
    if not headers:
        print("Failed to fetch headers, exiting...")
        sys.exit(1)

    ok_color = '\033[92m'
    warn_color = '\033[93m'
    end_color = '\033[0m'
    for header, value in headers.items():
        if value['warn']:
            if not value['defined']:
                print("Header '{}' is missing ... [ {}WARN{} ]".format(header, warn_color, end_color))
            else:
                print("Header '{}' contains value '{}'... [ {}WARN{} ]".format(
                    header, value['contents'], warn_color, end_color,
                ))
        else:
            if not value['defined']:
                print("Header '{}' is missing ... [ {}OK{} ]".format(header, ok_color, end_color))
            else:
                print("Header '{}' contains value '{}'... [ {}OK{} ]".format(
                    header, value['contents'], ok_color, end_color,
                ))

    https = header_check.test_https()
    if https['supported']:
        print("HTTPS supported ... [ {}OK{} ]".format(ok_color, end_color))
    else:
        print("HTTPS supported ... [ {}FAIL{} ]".format(warn_color, end_color))

    if https['certvalid']:
        print("HTTPS valid certificate ... [ {}OK{} ]".format(ok_color, end_color))
    else:
        print("HTTPS valid certificate ... [ {}FAIL{} ]".format(warn_color, end_color))

    if header_check.test_http_to_https():
        print("HTTP -> HTTPS redirect ... [ {}OK{} ]".format(ok_color, end_color))
    else:
        print("HTTP -> HTTPS redirect ... [ {}FAIL{} ]".format(warn_color, end_color))
