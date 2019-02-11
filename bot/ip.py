# Creates IP, TCP, and ICMP packets
# Calculates checksums
# Generates IP addresses

import socket
import struct
import random

import resolve
import checksum

from defs import (
    MIN_PORT, MAX_PORT, MAX_WIN_SIZE, IP_PREFIX_BLACKLIST,
    ICMP_ECHO_REQ, LOOPBACK_ADDR, TEST_ADDR, DEBUG
)

def is_private_ip(a, b, c):
    '''
        Checks the first three numbers of the IPv4 address and
        determines if it's a private IP address

        * a, b, c - the first three numbers of the IPv4 address
                    respectively

        Returns a boolean indicating if it is a private IP address
    '''

    if a == 10:
        return True
    if a == 192 and b == 168:
        return True
    if a == 100 and b >= 64 and c <= 127:
        return True
    if a == 172 and b >= 16 and c < 32:
        return True

    return False

def generate_random_public_ip():
    '''
        Generates a random public IP address to attack

        Returns a valid public IPv4 address
    '''

    while True:
        a = random.randint(1, 223)
        b = random.randint(1, 223)
        c = random.randint(1, 223)
        d = random.randint(1, 223)

        if a in IP_PREFIX_BLACKLIST:
            continue
        if a == int(LOOPBACK_ADDR[:3]):
            continue
        if is_private_ip(a, b, c):
            continue

        block = [a, b, c, d]
        addr = '.'.join(map(str, block))
        if resolve.resolve_host(addr) is None:
            continue

        return addr

def create_tcp_header(iph, dst_port, flags, payload):
    '''
        Creates a header for TCP packets

        * iph - the IP header used to help make the checksum
        * dst_port - the port to scan
        * flags - Indicates packet type
        * payload - An optional argument used for issuing commands
                    to the remote device or logging in

        Returns a string of binary data representing the header
    '''

    tcp_src = random.randint(MIN_PORT, MAX_PORT)
    tcp_dst = dst_port
    tcp_seq_num = 0
    tcp_ack_num = 0
    tcp_off = 5

    # tcp_fin = flags[0]
    # tcp_syn = flags[1]
    # tcp_rst = flags[2]
    # tcp_psh = flags[3]
    # tcp_ack = flags[4]
    # tcp_urg = flags[5]
    tcp_flags = 0
    for (i, flag) in enumerate(flags):
        tcp_flags += flag << i

    # print(tcp_flags)

    tcp_recv_win = socket.htons(MAX_WIN_SIZE)
    tcp_csum = 0
    tcp_urg_ptr = 0

    tcp_off_res = (tcp_off << 4) + 0

    tcph = struct.pack(
        '!HHLLBBHHH',
        tcp_src,
        tcp_dst,
        tcp_seq_num,
        tcp_ack_num,
        tcp_off_res,
        tcp_flags,
        tcp_recv_win,
        tcp_csum,
        tcp_urg_ptr
    )
    tcp_csum = checksum.compute_tcp_checksum(iph, tcph, payload)
    tcph = struct.pack(
        '!HHLLBBHHH',
        tcp_src,
        tcp_dst,
        tcp_seq_num,
        tcp_ack_num,
        tcp_off_res,
        tcp_flags,
        tcp_recv_win,
        socket.htons(tcp_csum),
        tcp_urg_ptr
    )

    return tcph

def create_ip_header(target, proto):
    '''
        Creates a header for IP packets

        * target - target IP address to send the packet
        * proto - Determines type of IP packet (TCP, ICMP, UDP, etc.)

        Returns a string of binary data representing the header
    '''

    ip_ver = 4
    ip_ihl = 5
    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    ip_tos = 0
    ip_tot_len = 84
    ip_id = random.randint(0, MAX_PORT)
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = proto
    ip_csum = 0
    if DEBUG:
        ip_src = socket.inet_aton(TEST_ADDR)
    else:
        # spoof source ip address
        fake_addr = socket.gethostbyname('www.google.com')
        ip_src = socket.inet_aton(fake_addr)
    ip_dst = socket.inet_aton(target)

    iph = struct.pack(
        '!BBHHHBBH4s4s',
        ip_ihl_ver,
        ip_tos,
        ip_tot_len,
        ip_id,
        ip_frag_off,
        ip_ttl,
        ip_proto,
        ip_csum,
        ip_src,
        ip_dst
    )
    ip_csum = checksum.compute_ip_checksum(iph)
    iph = struct.pack(
        '!BBHHHBBH4s4s',
        ip_ihl_ver,
        ip_tos,
        ip_tot_len,
        ip_id,
        ip_frag_off,
        ip_ttl,
        ip_proto,
        socket.htons(ip_csum),
        ip_src,
        ip_dst
    )

    return iph

def craft_tcp_packet(target, port, flags, payload=''):
    '''
        Crafts a custom TCP packet to send to the target. The process
        includes creating an IP header and a TCP header.

        * target - The target IP address
        * port - The port to scan on the target machine
        * flags - Used for TCP header indicating packet type
        * payload - An optional argument that can be used for issuing
                    commands to the remote device or logging in

        Returns a string of bytes to be sent over the wire
    '''

    iph = create_ip_header(target, socket.IPPROTO_TCP)
    tcph = create_tcp_header(iph, port, flags, payload)
    packet = iph + tcph + payload

    return packet

def create_icmp_header(payload):
    '''
        Creates a header for ICMP packets

        * payload - An optional argument used for issuing commands
                    to the remote device or logging in

        Returns a string of binary data representing the header
    '''

    icmp_type = ICMP_ECHO_REQ
    icmp_code = 0
    icmp_csum = 0
    icmp_id = random.randint(0, MAX_PORT)
    icmp_seq = 0
    icmph = struct.pack(
        '!BBHHH',
        icmp_type,
        icmp_code,
        icmp_csum,
        icmp_id,
        icmp_seq
    )
    icmp_csum = checksum.compute_icmp_checksum(icmph + payload)
    icmph = struct.pack(
        '!BBHHH',
        icmp_type,
        icmp_code,
        socket.htons(icmp_csum),
        icmp_id,
        icmp_seq
    )

    return icmph

def craft_icmp_packet(target, payload=''):
    '''
        Crafts a custom ICMP packet to send to the target. The process
        includes creating an IP header and a ICMP header.

        * target - The target IP address
        * payload - An optional argument that can be used for issuing
                    commands to the remote device or logging in

        Returns a string of bytes to be sent over the wire
    '''

    iph = create_ip_header(target, socket.IPPROTO_ICMP)
    icmph = create_icmp_header(payload)
    packet = iph + icmph + payload

    return packet
