#!/usr/bin/python

from lib.blindfuzzer import blindSeeker
import argparse
import sys
from urlparse import urlparse

# opt
parser = argparse.ArgumentParser(description='Blisqy is a tool to aid Web Security researchers to find Time-based Blind SQL injection on HTTP Endpoint/Headers.')
parser.add_argument('-u', "--url", required=True, help='specify the url to run')
parser.add_argument('-q', "--quiet", action="store_true", help='quiet mode will only log less info')
parser.add_argument('-e', "--early", action="store_true", help='exit scan on first finding')
parser.add_argument('-hd', '--header', action="store_true", default=False, help='fuzz http header')
parser.add_argument('-ho', '--header-only', dest="headonly", action="store_true", default=False, help='fuzz http header only')
parser.add_argument('-s', "--sleep", type=int, default=5, help='SQL injection sleep time (Default: 5)')
parser.add_argument('-t', "--timeout", type=int, default=10, help='socket connect/recv timeout value (Default: 10)')

args = parser.parse_args()
# print(args)

url = urlparse(args.url)

# Target Parameters
Server = url.netloc.split(":")[0]

Port = url.port
if Port == None:
    if url.scheme == "https":
        Port = 443
    elif url.scheme == "http":
        Port = 80
    else:
        print("error scheme: %s" % url.scheme)
        sys.exit(-1)

Endpoint = url.path
if Endpoint == "":
    Endpoint = "/"

Index = args.sleep

Method = 'GET'   # http method

# Provide files with tests for fuzzing
Headerfile = "fuzz-data/headers/small-headers.txt"
injectionfile = "fuzz-data/payloads/default.txt"

headerValue = Server
sleep = args.sleep
quiet = args.quiet
timeout = args.timeout
early = args.early
try:
    # Data to Fuzz our Target (in the format required)
    target_params = {
        'server': Server,
        'port': Port,
        'index': sleep,  # sleep time
        "timeout": timeout,
        'headersFile': Headerfile,
        'injectionFile': injectionfile,
        'method': Method,
        'endpoint': Endpoint,
        'socketTimeout': args.timeout,
        "headerValue": headerValue,
        "quiet": quiet,
        "early": early
    }

    # Use blindfuzzer methods to find a Timebased Blind-Sql Injection
    vulns = blindSeeker(target_params)
    vulns.print_info()
    if args.headonly:
        vulns.fuzz_header()
    else:
        vulns.fuzz_endpoint()
        if args.header:
            vulns.fuzz_header()
    vulns.findings(vulns.discover_vuln)

except Exception as err:
    print("Check Your Conection/Setup!")
    print("Hint: ")
    print(err)
