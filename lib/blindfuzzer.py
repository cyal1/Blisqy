import urllib
from socket import (socket, AF_INET, SOCK_STREAM)
from datetime import datetime
import gevent
import random
import httplib2
import time
import sys


class blindSeeker(object):

    def __init__(self, target_params):
        # Colors for Notifications and Errors
        self.red = "\x1b[1;31m"
        self.cyan = "\x1b[1;36m"
        self.green = "\x1b[1;32m"
        self.yellow = "\x1b[1;33m"
        self.clear = "\x1b[0m"

        # Our target
        self.endpoint= target_params['endpoint']
        self.server = target_params['server']
        self.port = target_params['port']
        self.index = target_params['index']
        self.headersFile = target_params['headersFile']
        self.injectionFile = target_params['injectionFile']
        self.HTTPVerb = target_params['method']
        self.discover_vuln = []

        # option
        self.timeout = target_params['timeout']
        self.headerValue = target_params['headerValue']
        self.quiet = target_params['quiet']
        self.early = target_params['early']


    def writeReport(self, report):
        stamp = datetime.now().strftime("-%H-%M-%S")
        fileName = "fuzz-reports/" + self.server + stamp + ".txt"
        with open(fileName, 'a') as log:
            log.write("{0}\n".format(report))


    def supportedHeaders(self, URL):
        webclient = httplib2.Http()
        header, content = webclient.request(URL, "GET")

        domain = URL.replace("http://", "")
        domain = domain.replace("/", "")
        domain = domain.replace(".", "")

        fileName = domain + "_headers.txt"

        fileName = "fuzz-data/headers/" + fileName

        reqestHeaders = open(fileName, 'w')
        for reqheader in header.keys():
            reqestHeaders.write(reqheader + "\n")

        print("[+] Headers File Written to : " + fileName + "\n")


    def baseline(self):
        '''Server Ping Before Fuzzing'''
        try:
            s = socket(AF_INET, SOCK_STREAM, 0)
            s.connect((self.server, self.port))

            # Send our Payload
            data = ""
            data += self.HTTPVerb+" " + self.endpoint + " HTTP/1.1\r\n"
            data += "Host: "
            data += self.server + "\r\n"
            data += "Connection: close\r\n\r\n"

            # Mark time before execution
            t1 = time.time()
            try:
                s.sendall(data)
                s.settimeout(self.timeout)
                s.recv(0)
            except Exception as err:
                print("socket recv timeout!")
                print(err)
                sys.exit()

            # Mark time after execution
            t2 = time.time()

            basetime = float("{0:.8f}".format(t2 - t1))
            return basetime

        except Exception as err:
            print("baseline")
            print(err)
            sys.exit()


    def findings(self, discover_vuln):
        # Report Header
        # fuzztarget = target_mg + target_val + "\n"
        # fuzztarget += baseIndex_mg + str(baseIndex) + "\n\n"

        # Report Note
        fuzzNote = '''=================== [ Key Terms] ===================
                    Index = Configured Constant (Delay)
                    Base Index Record = Server Ping Before Fuzzing
                    Benching Record  = Base Index Record + Index
                    Fuzzing Record = Time taken to process request with Index

                    ===================== [ Logic] =====================
                    If Fuzzing Record is greater than Benching Record,
                    treat as a positive; else, treat as a negative.\n\n\n'''

        # If Fuzzing got positive results, write report
        if len(self.discover_vuln) != 0:
            banner = "===================== [ LUCKY! ] ====================="
            msg = "[!] Found some +ve Results Check Fuzz Report for Details\n"
            print(
                self.red + banner + self.clear)

            print(self.cyan + msg + self.clear)

            self.writeReport(fuzzNote.replace("    ", ""))
            # self.writeReport(fuzztarget)

            for entry in discover_vuln:
                for field in entry:
                    self.writeReport(field)
                    print(field)

        # If fuzzing didn't get anything +ve
        else:
            banner = "==============[ TRY HARDER! ]====================="
            print(self.red + banner + self.clear)

            msg = "[-] Nothing Found. Adjust Sleeptime & Try more SQLi Payloads."
            print(self.cyan + msg + self.clear)


    def discover_header(self, target, counter):

        vulnHeader = target['vulnHeader']
        sqlInjection = target['sqlInjection']

        # Ping-time to WEB Server
        baseIndex = self.baseline()

        # Connect to WEB Server
        try:
            s = socket(AF_INET, SOCK_STREAM, 0)
            s.connect((self.server, self.port))

            injection = sqlInjection.replace("*index*", str(self.index)).replace("*space*"," ")


            # Send our Payload
            data = ""
            data += self.HTTPVerb+" " + self.endpoint + " HTTP/1.1\r\n"
            data += "Host: "
            data += self.server + ":" + str(self.port) + "\r\n"
            data += vulnHeader
            data += ": "
            data += self.headerValue + injection + "\r\n"
            data += "Connection: close\r\n\r\n"

            # Mark time before execution
            t1 = time.time()
            
            try:
                s.sendall(data)
                s.settimeout(self.timeout)
                s.recv(0)
            except Exception as err:
                print("socket recv timeout!")
                print(err)
                sys.exit()

            # Mark time after execution
            t2 = time.time()

            # Record TIme
            record = t2 - t1

            # Compare if time diffrence is greater than sleepTime
            record = float("{0:.8f}".format(record))
            Index = float("{0:.8f}".format(self.index))

            # benching = baseIndex + Index

            # timer = self.green + "[%s]" % time.asctime() + self.clear + "\n"
            counterid = self.cyan + "[Testcase%d] " % counter + self.clear
            injection = self.cyan + vulnHeader + ": " + self.headerValue + injection + self.clear + "\n"
            # benching_value = self.green + "Benching Record : " + self.clear + self.yellow + str(benching) + self.clear + "\n"
            Baseindex_value = self.green + "Baseindex Record : " + self.clear + self.yellow + str(
                baseIndex) + self.clear + "\n"
            fuzzrec = self.green + "Fuzzing Record : " + self.clear + self.yellow + str(record) + self.clear + "\n"
            spacer = "-----------------------------------\n"
            if self.quiet:
                sys.stdout.write(counterid + injection)
                sys.stdout.flush()
            else:
                sys.stdout.write(counterid + injection + Baseindex_value + fuzzrec + spacer)
                sys.stdout.flush()

            if record > Index:
                inj = "[+] Injection : " + injection
                head = "[+] Header: " + vulnHeader + "\n"
                IndRec = "[*] Baseindex Record : " + str(baseIndex)
                # baseInd = "[*] Benching Record : " + str(benching)
                fuzzRec = "[*] Fuzzing Record : " + str(record)
                inference = "[!] Test %d is Injectable." % counter
                lineSpace = "__________________________________"

                print(self.red + inference + self.clear)
                if not self.quiet:
                    print(lineSpace)

                fuzzout = [inj, head, IndRec,
                           fuzzRec, inference, lineSpace]

                self.discover_vuln.append(fuzzout)

                if self.early:
                    self.findings(self.discover_vuln)
                    sys.exit(0)
                fuzzRec = 0

            else:
                pass

        except Exception as err:
            print("discover_header")
            print(err)
            sys.exit()

    def discover_endpoint(self, target, counter):

        # vulnHeader = target['vulnHeader']
        sqlInjection = target['sqlInjection']

        # Ping-time to WEB Server
        baseIndex = self.baseline()
        # print(baseIndex)

        # Connect to WEB Server
        try:
            s = socket(AF_INET, SOCK_STREAM, 0)
            s.connect((self.server, self.port))

            injection = sqlInjection.replace("*index*", str(self.index)).replace("*space*", " ")

            # Send our Payload
            data = ""
            data += self.HTTPVerb+" " + self.endpoint + urllib.quote(injection, safe='+%') + " HTTP/1.1\r\n"  # urllib.quote_plus replace ' ' to '+'
            data += "Host: "
            data += self.server + "\r\n"
            data += "Connection: close\r\n\r\n"

            # Mark time before execution
            t1 = time.time()

            try:
                s.sendall(data)
                s.settimeout(self.timeout)
                s.recv(0)
            except Exception as err:
                print("socket recv timeout!")
                print(err)
                sys.exit()

            # Mark time after execution
            t2 = time.time()

            # Record TIme
            record = t2 - t1

            # Compare if time diffrence is greater than sleepTime
            record = float("{0:.8f}".format(record))
            Index = float("{0:.8f}".format(self.index))
            # print(baseIndex)
            # benching = baseIndex + Index

            # timer = self.green + "[%s]" % time.asctime() + self.clear + "\n"
            counterid = self.cyan + "[Testcase%0d]: " % counter + self.clear
            injection = self.cyan + self.endpoint + injection + self.clear + "\n"
            Baseindex_value = self.green + "Baseindex Record : " + self.clear + self.yellow + str(baseIndex) + self.clear + "\n"
            fuzzrec = self.green + "Fuzzing Record : " + self.clear + self.yellow + str(record) + self.clear + "\n"
            spacer = "-----------------------------------\n"
            if self.quiet:
                sys.stdout.write(counterid + injection)
                sys.stdout.flush()
            else:
                sys.stdout.write(counterid + injection + Baseindex_value + fuzzrec + spacer)
                sys.stdout.flush()
            # print("-"*100)
            if record > Index:
                inj = "[+] Injection : " + injection
                head = "[+] Endpoint : " + self.endpoint + "\n"
                # IndRec = "[*] Index Record : " + str(baseIndex)
                baseInd = "[*] Baseindex Record : " + str(baseIndex)
                fuzzRec = "[*] Fuzzing Record : " + str(record)
                inference = "[!] [Testcase%d] is Injectable." % counter
                lineSpace = "__________________________________"

                print(self.red + inference + self.clear)
                if not self.quiet:
                    print(lineSpace)

                fuzzout = [inj, head, baseInd,
                           fuzzRec, inference, lineSpace]

                self.discover_vuln.append(fuzzout)

                if self.early:
                    self.findings(self.discover_vuln)
                    sys.exit(0)
                fuzzRec = 0

            else:
                pass

        except Exception as err:
            print("discover_header")
            print(err)
            sys.exit()
    def print_info(self):

        target_mg = "\n[+] Fuzzer Running  : "
        target_val = self.server + ":" + str(self.port)

        print(self.cyan + target_mg +
              self.clear + self.yellow + target_val + self.clear)

        baseIndex = self.baseline()

        baseIndex_vl = str(float("{0:.8f}".format(baseIndex)))
        baseIndex_mg = "\n[+] Base Index Record for Target : "
        baseIndex_ep = "[+] Base Endpoint for Target : "

        print(self.cyan + baseIndex_ep + self.clear + self.yellow + self.endpoint + self.clear +
              self.cyan + baseIndex_mg + self.clear + self.yellow + baseIndex_vl + self.clear)

    def fuzz_header(self):
        
        counter = 1
        banner = "\n============== start Furzzzn header ==============="
        print(self.red + banner + self.clear + "\n")
        threads = []

        # Read headers File
        with open(self.headersFile) as Header_Requests:
            for Header in Header_Requests:

                # Read Injection File
                with open(self.injectionFile) as injectionFile:
                    for Injection in injectionFile:

                        # Create Our Fuzzing Target
                        target = {
                            'vulnHeader': Header.strip(),
                            'sqlInjection': Injection.strip()
                        }

                        # Run Fuzzer with target
                        # found = gevent.spawn()
                        # gevent.spawn(self.discover(target, counter))

                        threads.append(gevent.spawn(
                        self.discover_header(target, counter)))
                        
                        # Increment Test Counter
                        counter = counter + 1

        gevent.joinall(threads)

        # self.findings(self.discover_vuln)

    def fuzz_endpoint(self):

        counter = 1
        banner = "\n============== start Furzzzn endpoint ==============="
        print(self.red + banner + self.clear + "\n")
        threads = []

        # Read Inject File
        with open(self.injectionFile) as injectionFile:
            for Injection in injectionFile:
                # Create Our Fuzzing Target
                target = {
                    # 'vulnHeader': Header.strip(),
                    'sqlInjection': Injection.strip()
                }

                # Run Fuzzer with target
                # found = gevent.spawn()
                # gevent.spawn(self.discover(target, counter))

                threads.append(gevent.spawn(
                    self.discover_endpoint(target, counter)))

                # Increment Test Counter
                counter = counter + 1


        gevent.joinall(threads)

        # self.findings(self.discover_vuln)