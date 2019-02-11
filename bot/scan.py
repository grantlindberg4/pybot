# Scans devices for open ports and reports vulnerable devices

import socket
import sys
import select
import struct
import errno

import ip

from defs import (
    MAX_SCANS, TIMEOUT_LEN, IP_HEADER_LEN, TCP_HEADER_LEN, PORT_STATE,
    RESPONSE_TYPE
)

def is_open_port(flags):
    '''
        Checks the flags from the packet to see if the port is open

        * flags - The flags from the TCP header

        Returns a boolean indicating if the port is open

        Notes: We really only need the SYN flag since sometimes we
        will experience a rare split-handshake scenario in which the
        ACK bit is not present
    '''

    syn = (flags & 2) >> 1
    rst = (flags & 4) >> 2
    # ack = (flags & 16) >> 4
    fin = flags & 1

    return syn and not (rst or fin)

def is_scan_response(target, sender, ip_proto, tcp_src, port):
    '''
        Checks the next incoming packet to determine if it is a
        response to the SYN packet

        * target - The target IP address
        * sender - The IPv4 address sender
        * ip_proto - The protocol of the IP header
        * tcp_src - TCP source port
        * port - target port currently being scanned

        Returns a boolean indicating if the packet is a response to
        the SYN scan and the port is open
    '''

    if sender != target:
        return False
    if ip_proto != socket.IPPROTO_TCP:
        return False
    if tcp_src != port:
        return False

    return True

def interpret_response(target, port, resp):
    '''
        Unpacks the next incoming packet to determine if it is a
        response to the SYN packet

        * target - The target IP address
        * port - target port currently being scanned
        * resp - packet/address pair representing the incoming packet

        Returns a RESPONSE_TYPE indicating if the port is accessible
    '''

    packet = resp[0]
    addr = resp[1]

    iph = struct.unpack('!BBHHHBBH4s4s', packet[:IP_HEADER_LEN])
    ip_proto = iph[6]
    tcph = struct.unpack(
        '!HHLLBBHHH',
        packet[IP_HEADER_LEN:IP_HEADER_LEN+TCP_HEADER_LEN]
    )
    tcp_src = tcph[0]
    if is_scan_response(target, addr[0], ip_proto, tcp_src, port):
        flags = tcph[5]
        if is_open_port(flags):
            return RESPONSE_TYPE['OK']
        else:
            return RESPONSE_TYPE['DENIED']
    else:
        return RESPONSE_TYPE['OTHER']

def await_response(sock, target, port):
    '''
        Waits for a packet to arrive

        * sock - raw socket that sent the SYN packets
        * target - The target IP address
        * port - target port currently being scanned

        Returns a RESPONSE_TYPE indicating if the port is accessible
    '''

    while True:
        try:
            # Needed for nonblocking IO
            ready = select.select([sock,], [], [], TIMEOUT_LEN)
            if ready[0]:
                resp = sock.recvfrom(4096)
            else:
                return RESPONSE_TYPE['NO_RESPONSE']
        except IOError as e:
            err = e.args[0]
            if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
                return RESPONSE_TYPE['NO_RESPONSE']
            else:
                print('[!] Error receiving packet: %s' % e)
                return RESPONSE_TYPE['NO_RESPONSE']

        status = interpret_response(target, port, resp)
        if status == RESPONSE_TYPE['OTHER']:
            continue
        else:
            return status

def scan_port(target, port):
    '''
        Sends SYN packets to the given target until an open port is
        found. If a RST packet is received, the port is closed. If
        a SYN/ACK packet is received, the port is open.

        * target - The target IP address
        * port - The port to scan

        Returns a PORT_STATE indicating whether or not the target can
        be attacked
    '''

    print('Scanning %s:%d...' % (target, port))
    try:
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            socket.IPPROTO_TCP
        )
    except IOError as e:
        print('[!] Failed to create raw socket')
        print('    Unable to scan %s' % target)
        print('    Error: %s' % e)
        sys.exit(1)

    sock.setblocking(False)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except IOError as e:
        print('[!] Failed to set IP_HDRINCL')
        print('    Unable to scan %s' % target)
        print('    Error: %s' % e)
        sock.close()
        sys.exit(1)

    flags = [0, 1, 0, 0, 0, 0]
    syn_pack = ip.craft_tcp_packet(target, port, flags)

    for scans in range(MAX_SCANS):
        if scans != 0:
            print('[!] Retrying %s:%d...' % (target, port))

        sent_bytes = sock.sendto(syn_pack, (target, 0))
        if sent_bytes <= 0:
            print(
                '[!] Failed to send SYN packet to %s:%d'
                % (target, port)
            )
            continue

        resp = await_response(sock, target, port)

        if resp == RESPONSE_TYPE['OK']:
            sock.close()
            return PORT_STATE['OPEN']
        elif resp == RESPONSE_TYPE['DENIED']:
            sock.close()
            return PORT_STATE['CLOSED']

    sock.close()
    return PORT_STATE['FILTERED']

def scan_ports(target, ports):
    '''
        Scans a list of ports and marks those that are open

        * target - The target IP address
        * ports - The list of ports to scan

        Returns a list of open ports
    '''

    open_ports = []
    for port in ports:
        if scan_port(target, port) == PORT_STATE['OPEN']:
            print('[+] Found open port: %s:%d\n' % (target, port))
            open_ports.append(port)

    return open_ports
