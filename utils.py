import re
from typing import Tuple, Dict
import ssl
import socket

from constants import EVAL_WARN, EVAL_OK

# X-Frame-Options
def eval_x_frame_options(contents: str) -> Tuple[int, list]:
    if contents.lower().strip() in ['deny', 'sameorigin']:
        return EVAL_OK, []

    return EVAL_WARN, []

# X-Content-Type-Options
def eval_content_type_options(contents: str) -> Tuple[int, list]:
    if contents.lower().strip() == 'nosniff':
        return EVAL_OK, []

    return EVAL_WARN, []

# X-XSS-Protection
def eval_x_xss_protection(contents: str) -> Tuple[int, list]:
    # This header is deprecated but still used quite a lot
    #
    # value '1' is dangerous because it can be used to block legit site features. If this header is defined, either
    # one of the below values if recommended
    if contents.lower().strip().replace(' ', '') in ['1;mode=block', '0']:
        return EVAL_OK, []

    return EVAL_WARN, []


class HSTSParser():
    def __init__(self, content:str) -> None:
        self.content = content.lower()
        self.max_age = 0
        self.preload = False
        self.includeSubDomain = False
        self.isFormValid = self.check_sts_format()
    
    def parse_max_age(max_age_content) -> int:
        match = re.search(r'max-age=(\d+)', max_age_content)
        if match:
            return int(match.group(1))
        # max-age can be quoted
        # ref: https://www.rfc-editor.org/rfc/rfc6797#section-6.2
        match = re.search(r'max-age="(\d+)"', max_age_content)
        if match:
            return int(match.group(1))
        return None

    def check_sts_format(self) -> bool:
        contents = self.content.split(";")
        for idx, content in enumerate(contents):
            max_age = HSTSParser.parse_max_age(content)
            if max_age:
                self.max_age = max_age
                del contents[idx]
                if len(contents) == 0:
                    return True
                break
        else:
            return False
        
        for idx, content in enumerate(contents):
            if "includesubdomains" in content.strip():
                self.includeSubDomain = True
                del contents[idx]
                break
        else:
            return False
        
        if len(contents) == 1:
            if contents[0].strip() == "preload":
                self.preload = True
                return True
            else:
                return False
        else:
            return True

# Strict-Transport-Security (HSTS)
# https://www.rfc-editor.org/rfc/rfc6797
def eval_sts(contents: str) -> Tuple[int, list]:
    MAX_AGE_MINIMUM = 480
    hsts_result = HSTSParser(contents)
    if hsts_result.isFormValid: 
        # restriction of preload
        # ref : https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security#preload
        if hsts_result.preload and hsts_result.max_age < 31536000: # 1 year
            return EVAL_WARN, ["Preload is not valid when max-age < 31536000"]
        
        if hsts_result.max_age < MAX_AGE_MINIMUM:
            return EVAL_WARN, [f"max-age too small, should be greater than {MAX_AGE_MINIMUM} seconds"]
        
        return EVAL_OK, []
    else:
        return EVAL_WARN, []

def eval_csp(contents: str) -> Tuple[int, list]:
    UNSAFE_RULES = {
        "script-src": ["*", "'unsafe-eval'", "data:", "'unsafe-inline'"],
        "frame-ancestors": ["*"],
        "form-action": ["*"],
        "object-src": ["*"],
    }

    # There are no universal rules for "safe" and "unsafe" CSP directives, but we apply some common sense here to
    # catch some obvious lacks or poor configuration
    csp_unsafe = False
    csp_notes = []

    csp_parsed = csp_parser(contents)

    for rule in UNSAFE_RULES:
        if rule not in csp_parsed:
            if '-src' in rule and 'default-src' in csp_parsed:
                # fallback to default-src
                for unsafe_src in UNSAFE_RULES[rule]:
                    if unsafe_src in csp_parsed['default-src']:
                        csp_unsafe = True
                        csp_notes.append("Directive {} not defined, and default-src contains unsafe source {}".format(
                            rule, unsafe_src))
            elif 'default-src' not in csp_parsed:
                csp_notes.append("No directive {} nor default-src defined in the Content Security Policy".format(rule))
                csp_unsafe = True
        else:
            for unsafe_src in UNSAFE_RULES[rule]:
                if unsafe_src in csp_parsed[rule]:
                    csp_notes.append("Unsafe source {} in directive {}".format(unsafe_src, rule))
                    csp_unsafe = True

    if csp_unsafe:
        return EVAL_WARN, csp_notes

    return EVAL_OK, []


def eval_version_info(contents: str) -> Tuple[int, list]:
    # Poor guess whether the header value contain something that could be a server banner including version number
    if len(contents) > 3 and re.match(".*[^0-9]+.*\\d.*", contents):
        return EVAL_WARN, []

    return EVAL_OK, []

# Permissions-Policy 
def eval_permissions_policy(contents: str) -> Tuple[int, list]:
    # Configuring Permission-Policy is very case-specific and it's difficult to define a particular recommendation.
    # We apply here a logic, that access to privacy-sensitive features and payments API should be restricted.

    pp_parsed = permissions_policy_parser(contents)
    notes = []
    pp_unsafe = False
    RESTRICTED_PRIVACY_POLICY_FEATURES = ['camera', 'geolocation', 'microphone', 'payment']

    for feature in RESTRICTED_PRIVACY_POLICY_FEATURES:
        if feature not in pp_parsed or '*' in pp_parsed.get(feature):
            pp_unsafe = True
            notes.append("Privacy-sensitive feature '{}' is not restricted to specific origins.".format(feature))

    if pp_unsafe:
        return EVAL_WARN, notes

    return EVAL_OK, []

# Referrer-Policy
def eval_referrer_policy(contents: str) -> Tuple[int, list]:
    for content in contents.split(','):
        if content.lower().strip() not in [
            'no-referrer',
            'no-referrer-when-downgrade',
            'origin',
            'origin-when-cross-origin',
            'same-origin',
            'strict-origin',
            'strict-origin-when-cross-origin',
        ]:
            return EVAL_WARN, ["Unsafe contents: {}".format(contents)]
    else:
        return EVAL_OK, []

    

def get_cipher_suite(hostname, port=443):
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cipher_suite = ssock.cipher()
            return cipher_suite

def eval_cipher_suite(cipher_suite:Tuple[str, str,int]) -> Tuple[int, list]:
    if cipher_suite[1] == "TLSv1.3":
        return EVAL_OK, []
    elif "DHE" in cipher_suite[0]:
        return EVAL_OK, []
    else:
        return EVAL_WARN, ["Unsafe cipher suite: {}".format(cipher_suite)]

def check_cipher_suite(hostname:str, port:int=443) -> Tuple[int, list]:
    cipher_suite = get_cipher_suite(hostname, port)
    return eval_cipher_suite(cipher_suite)

def csp_parser(contents: str) -> dict:
    csp = {}
    directives = contents.split(";")
    for directive in directives:
        directive = directive.strip().split()
        if directive:
            csp[directive[0]] = directive[1:] if len(directive) > 1 else []

    return csp


def permissions_policy_parser(contents: str) -> dict:
    policies = contents.split(",")
    retval = {}
    for policy in policies:
        match = re.match('^(\\w*)=(\\(([^\\)]*)\\)|\\*|self)$', policy)
        if match:
            feature = match.groups()[0]
            feature_policy = match.groups()[2] if match.groups()[2] is not None else match.groups()[1]
            retval[feature] = feature_policy.split()

    return retval


def print_ok(msg: str):
    OK_COLOR = '\033[92m'
    END_COLOR = '\033[0m'
    print("{} ... [ {}OK{} ]".format(msg, OK_COLOR, END_COLOR))


def print_warning(msg: str):
    WARN_COLOR = '\033[93m'
    END_COLOR = '\033[0m'
    print("{} ... [ {}WARN{} ]".format(msg, WARN_COLOR, END_COLOR))
