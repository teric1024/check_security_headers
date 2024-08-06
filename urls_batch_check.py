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

def check_default_pass_header(header:str):
    return header in ['Permissions-Policy', 'Content-Security-Policy']

def result_to_report_row(result, url):
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

        if check_default_pass_header(header_name) and header_info['defined']:
            report_row[header_name] = "OK" 
    
    return report_row

def readable_row_name(header_name:str):
    words = header_name.split("-")
    capitalized_words = [word.capitalize() for word in words]
    row_name = '-'.join(capitalized_words)
    return row_name.replace("Xss", "XSS")

def url_to_filename(url):
    return url.split("://")[-1] + ".json"

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

def main(url_file_path, output_csv_path):
    urls = get_target_urls(url_file_path)
    report = []
    for url in urls:
        url = url.strip()
        result = validate_url(url)
        save_if_warn(url, result)
        report_row = result_to_report_row(result, url)
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
    