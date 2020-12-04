#!/usr/bin/python

from lib.blindfuzzer import blindSeeker
import argparse
import socket
import sys
from urlparse import urlparse



# opt
parser = argparse.ArgumentParser(description='Detect blind sql inject via http endpoint/header')
parser.add_argument('-u', "--url", required=True, help='Required a url')
parser.add_argument('-q', "--quiet", action="store_true", help='Quiet mode will only log less info')
parser.add_argument('-e', "--early", action="store_true", help='Exit scan on first finding')
parser.add_argument('-t', "--timeout", type=int, default=8, help='Socket recv timeout value (Default: 8)')
parser.add_argument('-s', "--sleep", type=int, default=2, help='SQL injection payload sleep time (Default: 2)')
parser.add_argument('--header', action="store_true", default=False, help='Fuzz http header')
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
Headerfile = "fuzz-data/headers/header-s.txt"
injectionfile = "fuzz-data/payloads/default.txt"

headerValue = Server
sleep = args.sleep
quiet = args.quiet
timeout = args.timeout
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
        "quiet": quiet
    }

    # Use blindfuzzer methods to find a Timebased Blind-Sql Injection
    vulns = blindSeeker(target_params)
    vulns.print_info()
    vulns.fuzz_endpoint()
    if args.header:
        vulns.fuzz_header()
    vulns.findings(vulns.discover_vuln)

except Exception as err:
    print("Check Your Conection/Setup!")
    print("Hint: ")
    print(err)
