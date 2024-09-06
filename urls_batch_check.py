#!/usr/bin/env python3
from securityheaders import SecurityHeaders,SecurityHeadersException
import utils
import constants

import argparse
import csv
import json
import os

def validate_url(url:str):
    """
    Validates the security headers of a given URL.

    Args:
        url (str): The URL to validate.

    Returns:
        dict or None: A dictionary containing the security headers of the URL if successful, 
                      or None if an error occurred.

                      Dictionary format example:
                      {
                          "x-xss-protection": {
                              "defined": True,
                              "warn": True,
                              "contents": "1; mode=block",
                              "notes": "", # invalid description here
                          },
                          ...
                      }

    Raises:
        None
    """
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
        if header_check.port is not None:
            res, notes = utils.check_cipher_suite(header_check.hostname, header_check.port)
        else:
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
        lines = f.readlines()
        lines = [line.replace("\"", "").replace("'", "") for line in lines]
        return [line.strip() for line in lines]

def result_to_report_row(result, url, pass_check_header_list):
    report_row = {}
    report_row["url"] = url
    if result is None:
        return report_row
    
    for header_name, header_info in result.items():
        header_name = readable_row_name(header_name)
        if not header_info['defined']:
            report_row[header_name] = "N/A"
        elif header_info['warn']:
            report_row[header_name] = "NO"
        else:
            report_row[header_name] = "OK"

        if (header_name in pass_check_header_list) and header_info['defined']:
            report_row[header_name] = "OK" 
    
    return report_row

def readable_row_name(header_name:str):
    words = header_name.split("-")
    capitalized_words = [word.capitalize() for word in words]
    row_name = '-'.join(capitalized_words)
    return row_name.replace("Xss", "XSS")

def url_to_filename(url:str):
    no_protocal_url = url.split("://")[-1]
    return no_protocal_url.replace("/", "_").replace("?","-") + ".json"

def save_if_warn(url, result):
    directory_path = "./not_secure_urls/"
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)
    filepath = directory_path + url_to_filename(url)

    if result is None:
        return
    
    warning_info = {}
    for header_name, header_info in result.items():
        if header_info['warn']:
            warning_info[header_name] = header_info
    with open(filepath, "w") as f:
        json.dump(warning_info, f)

def main(url_file_path, output_csv_path, pass_check_header_list):
    urls = get_target_urls(url_file_path)
    report = []
    for url in urls:
        url = url.strip()
        result = validate_url(url)
        save_if_warn(url, result)
        report_row = result_to_report_row(result, url, pass_check_header_list)
        report.append(report_row)
    with open(output_csv_path, "w", newline="") as f:
        headers_to_check = [
            'url',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Referrer-Policy',
            'X-Content-Type-Options',
            'Content-Security-Policy',
            'Permissions-Policy',
            'Forward-Secrecy',
            'Feature-Policy',
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
    parser.add_argument('--pass_csp_header', dest='pass_csp_header',
                        help='pass check for csp header', action='store_true')
    parser.add_argument('--pass_permissions_policy', dest='pass_permissions_policy',
                        help='pass check for permissions policy', action='store_true')
    args = parser.parse_args()
    return args

def make_pass_check_header_list(args):
    pass_check_header_list = []
    if args.pass_csp_header:
        pass_check_header_list.append('Content-Security-Policy')
    if args.pass_permissions_policy:
        pass_check_header_list.append('Permissions-Policy')
    return pass_check_header_list

if __name__ == "__main__":
    args = parse_args()
    pass_check_header_list = make_pass_check_header_list(args)
    main(args.target_url_file, args.output_csv, pass_check_header_list)
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
    