import urllib
from socket import (socket, AF_INET, SOCK_STREAM)
from datetime import datetime
import gevent
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
        self.endpoint = target_params['endpoint']
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
            s.settimeout(self.timeout)
            s.connect((self.server, self.port))
            s.settimeout(None)

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
                self.findings(self.discover_vuln)
                sys.exit()

            # Mark time after execution
            t2 = time.time()

            basetime = float("{0:.8f}".format(t2 - t1))
            return basetime

        except Exception as err:
            print("socket connect timeout")
            print(err)
            self.findings(self.discover_vuln)
            sys.exit()


    def findings(self, discover_vuln):
        # Report Header
        # fuzztarget = target_mg + target_val + "\n"
        # fuzztarget += baseIndex_mg + str(baseIndex) + "\n\n"

        # Report Note
        fuzzNote = '''=================== [ Key Terms] ===================
                    Payload Sleep = The SQLI Payload Sleep Value
                    Baseindex Record = Server Ping Before Fuzzing
                    Fuzzing Record = Time taken to process request with Index

                    ===================== [ Logic] =====================
                    If Fuzzing Record is greater than Baseindex Record,
                    treat as a positive; else, treat as a negative.\n'''

        # If Fuzzing got positive results, write report
        if len(self.discover_vuln) != 0:
            banner = "\n===================== [ LUCKY! ] ====================="
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
            banner = "\n===================== [ TRY HARDER! ] ====================="
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
            s.settimeout(self.timeout)
            s.connect((self.server, self.port))
            s.settimeout(None)

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
                self.findings(self.discover_vuln)
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
            injection = self.cyan + vulnHeader + ": " + self.headerValue + injection + self.clear
            # benching_value = self.green + "Benching Record : " + self.clear + self.yellow + str(benching) + self.clear + "\n"
            Baseindex_value = self.green + "Baseindex Record : " + self.clear + self.yellow + str(
                baseIndex) + self.clear + "\n"
            fuzzrec = self.green + "Fuzzing Record : " + self.clear + self.yellow + str(record) + self.clear + "\n"
            spacer = "-----------------------------------\n"
            if self.quiet:
                sys.stdout.write(counterid + injection + "\n")
                sys.stdout.flush()
            else:
                sys.stdout.write(counterid + injection + "\n" + Baseindex_value + fuzzrec + spacer)
                sys.stdout.flush()

            if record > Index:
                target = "[+] Server: " + self.server + ":" + str(self.port)
                inj = "[+] Injection : " + injection
                head = "[+] Header: " + vulnHeader
                payloadSleep = "[*] Payload Sleep : " + str(self.index)
                IndRec = "[*] Baseindex Record : " + str(baseIndex)
                # baseInd = "[*] Benching Record : " + str(benching)
                fuzzRec = "[*] Fuzzing Record : " + str(record)
                inference = "[!] [Testcase%d] is Injectable." % counter
                lineSpace = "__________________________________"

                print(self.red + inference + self.clear)
                if not self.quiet:
                    print(lineSpace)

                fuzzout = [target, head, inj, payloadSleep, IndRec,
                           fuzzRec, inference, lineSpace]

                self.discover_vuln.append(fuzzout)

                if self.early:
                    self.findings(self.discover_vuln)
                    sys.exit()
                fuzzRec = 0

            else:
                pass

        except Exception as err:
            print("socket connect timeout!")
            print(err)
            self.findings(self.discover_vuln)
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
            s.settimeout(self.timeout)
            s.connect((self.server, self.port))
            s.settimeout(None)

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
                self.findings(self.discover_vuln)
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
            counterid = self.cyan + "[Testcase%d]: " % counter + self.clear
            injection = self.cyan + self.endpoint + injection + self.clear
            Baseindex_value = self.green + "Baseindex Record : " + self.clear + self.yellow + str(baseIndex) + self.clear + "\n"
            fuzzrec = self.green + "Fuzzing Record : " + self.clear + self.yellow + str(record) + self.clear + "\n"
            spacer = "-----------------------------------\n"
            if self.quiet:
                sys.stdout.write(counterid + injection + "\n")
                sys.stdout.flush()
            else:
                sys.stdout.write(counterid + injection + "\n" + Baseindex_value + fuzzrec + spacer)
                sys.stdout.flush()
            # print("-"*100)
            if record > Index:
                target = "[+] Server: " + self.server + ":" + str(self.port)
                inj = "[+] Injection : " + injection
                head = "[+] Endpoint : " + self.endpoint
                # IndRec = "[*] Index Record : " + str(baseIndex)
                payloadSleep = "[*] Payload Sleep : " + str(self.index)
                baseInd = "[*] Baseindex Record : " + str(baseIndex)
                fuzzRec = "[*] Fuzzing Record : " + str(record)
                inference = "[!] [Testcase%d] is Injectable." % counter
                lineSpace = "__________________________________"

                print(self.red + inference + self.clear)
                if not self.quiet:
                    print(lineSpace)

                fuzzout = [target, head, inj, payloadSleep, baseInd,
                           fuzzRec, inference, lineSpace]

                self.discover_vuln.append(fuzzout)

                if self.early:
                    self.findings(self.discover_vuln)
                    sys.exit()
                fuzzRec = 0

            else:
                pass

        except Exception as err:
            print("socket connect timeout!")
            print(err)
            self.findings(self.discover_vuln)
            sys.exit()
    def print_info(self):


        print(""" 
 ____  _ _                 _ 
| __ )| (_)___  __ _ _   _| |
|  _ \| | / __|/ _` | | | | |
| |_) | | \__ \ (_| | |_| |_|
|____/|_|_|___/\__, |\__, (_)
                  |_||___/ 
                """)

        target_mg = "[+] Fuzzer Running  : "
        target_val = self.server + ":" + str(self.port) + "\n"
        baseIndex_ep = "[+] Base Endpoint for Target : "
        print(self.cyan + target_mg + self.clear + self.yellow + target_val + self.clear +
              self.cyan + baseIndex_ep + self.clear + self.yellow + self.endpoint + self.clear)

        baseIndex = self.baseline()
        baseIndex_vl = str(float("{0:.8f}".format(baseIndex)))
        baseIndex_mg = "[+] Base Index Record for Target : "
        print(self.cyan + baseIndex_mg + self.clear + self.yellow + baseIndex_vl + self.clear + "\n")

    def fuzz_header(self):
        
        counter = 1
        banner = "\n===================== start Furzzzn header ==============="
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
        banner = "===================== start Furzzzn endpoint ==============="
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
