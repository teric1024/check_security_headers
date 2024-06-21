#!/usr/bin/env python3
from securityheaders import SecurityHeaders,SecurityHeadersException
import utils
import constants

import argparse
import csv

def validate_url(url:str):
    try:
        header_check = SecurityHeaders(url, 2, False, False)
        header_check.fetch_headers()
        headers = header_check.check_headers()
    except SecurityHeadersException as e:
        print(f"Error: cannot get headers from {url}.  Exception: {e}")
        headers = None

    if not headers:
        print(f"Failed to get headers from {url}.")
        return None
    
    if header_check.protocol_scheme == "https":
        res, notes = utils.check_cipher_suite(header_check.hostname)
        headers["forward-secrecy"] = {
                    'defined': True,
                    'warn': res == constants.EVAL_WARN,
                    'contents': "none",
                    'notes': notes,
                }
    else:
        headers["forward-secrecy"] = {
                    'defined': True,
                    'warn': True,
                    'contents': "none",
                    'notes': "needs https",
                }
    return headers

def get_target_urls(url_file_path):
    with open(url_file_path, "r") as f:
        return f.readlines()
    # return ["adocday.com"]

def check_default_pass_header(header:str):
    return header in ['permissions-policy', 'content-security-policy']

def result_to_report_row(result, url):
    report_row = {}
    report_row["url"] = url
    if result is None:
        return report_row
    
    for header_name, header_info in result.items():
        if not header_info['defined']:
            report_row[header_name] = "N/A"
        elif header_info['warn']:
            report_row[header_name] = "NO"
        else:
            report_row[header_name] = "OK"

        if check_default_pass_header(header_name) and header_info['defined']:
            report_row[header_name] = "OK" 
    
    return report_row


def main(url_file_path, output_csv_path):
    urls = get_target_urls(url_file_path)
    report = []
    for url in urls:
        url = url.strip()
        result = validate_url(url)
        report_row = result_to_report_row(result, url)
        report.append(report_row)
    with open(output_csv_path, "w", newline="") as f:
        headers_to_check = [
            'url',
            'x-frame-options',
            'x-xss-protection',
            'strict-transport-security',
            'referrer-policy',
            'x-content-type-options',
            'content-security-policy',
            'permissions-policy',
            'forward-secrecy',
            'feature-policy',
        ]
        w = csv.DictWriter(f, headers_to_check)
        w.writeheader()
        for row in report:
            w.writerow(row)

def parse_args():
    parser = argparse.ArgumentParser(description='Check HTTP security headers',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--target_url_file', dest='target_url_file', default='urls.txt', type=str,
                        help='txt file including urls')
    parser.add_argument('--output_csv', dest='output_csv', default='output.csv', type=str,
                        help='result csv file path')
    args = parser.parse_args()
    return args

if __name__ == "__main__":
    args = parse_args()
    main(args.target_url_file, args.output_csv)
    print("""
⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣀⣀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣾⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠀⠀⠀⠀⢀⠀⠈⡇⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⠀⠁⠀⠘⠁⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠈⠀⠀⡇⠀⠀⠀⠀
⣀⣀⣀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠄⠀⠀⠸⢰⡏⠉⠳⣄⠰⠀⠀⢰⣷⠶⠛⣧⠀
⢻⡀⠈⠙⠲⡄⣿⠀⠀⠀⠀⠀⠀⠀⠠⠀⢸⠀⠀⠀⠈⠓⠒⠒⠛⠁⠀⠀⣿⠀
⠀⠻⣄⠀⠀⠙⣿⠀⠀⠀⠈⠁⠀⢠⠄⣰⠟⠀⢀⡔⢠⠀⠀⠀⠀⣠⠠⡄⠘⢧
⠀⠀⠈⠛⢦⣀⣿⠀⠀⢠⡆⠀⠀⠈⠀⣯⠀⠀⠈⠛⠛⠀⠠⢦⠄⠙⠛⠃⠀⢸
⠀⠀⠀⠀⠀⠉⣿⠀⠀⠀⢠⠀⠀⢠⠀⠹⣆⠀⠀⠀⠢⢤⠠⠞⠤⡠⠄⠀⢀⡾
⠀⠀⠀⠀⠀⢀⡿⠦⢤⣤⣤⣤⣤⣤⣤⣤⡼⣷⠶⠤⢤⣤⣤⡤⢤⡤⠶⠖⠋⠀
⠀⠀⠀⠀⠀⠸⣤⡴⠋⠸⣇⣠⠼⠁⠀⠀⠀⠹⣄⣠⠞⠀⢾⡀⣠⠃⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠁⠀⠀⠀⠀⠀
    Nyanyanyanyanyanyanya!
          
          completed!
          """)
    