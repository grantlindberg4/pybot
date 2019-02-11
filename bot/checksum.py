# Calculates checksums for IP and TCP headers

import struct
import sys

def compute_ip_checksum(src):
    '''
        Computes an IP checksum

        * src - The source string of bytes

        Returns an integer representing the checksum
    '''

    s = 0
    for i in range(0, len(src), 2):
        a = ord(src[i])
        if (i+1) < len(src):
            b = ord(src[i+1])
            s += a + (b << 8)
        elif (i+1) == len(src):
            s += a
        else:
            print('Error calculating checksum')
            sys.exit(1)
    s += (s >> 16)
    s = ~s & 0xffff

    return s


def compute_tcp_checksum(iph, tcph, payload):
    '''
        Computes a generic checksum for TCP headers using a pseudo-
        header from the IP header

        * iph - The IP header
        * tcph - The TCP header
        * payload - Data to be sent in the header (mostly for logins)

        Returns an integer representing the checksum
    '''

    data = struct.unpack('!BBHHHBBH4s4s', iph)
    reserved = 0
    tcp_len = len(tcph) + len(payload)

    pseudoh = struct.pack(
        '!4s4sBBH',
        data[8],
        data[9],
        reserved,
        data[6],
        tcp_len
    )

    src = pseudoh + tcph + payload
    s = compute_ip_checksum(src)

    return s

def compute_icmp_checksum(src):
    # Network data may be big-endian, hosts are typically little-endian
    count_to = (int(len(src) / 2)) * 2
    my_sum = 0
    count = 0
    low = 0
    high = 0

    while count < count_to:
        if sys.byteorder == "little":
            low = src[count]
            high = src[count + 1]
        else:
            low = src[count + 1]
            high = src[count]
        my_sum = my_sum + (ord(high)*256 + ord(low))
        count += 2
    if count_to < len(src):
        low = src[len(src) - 1]
        my_sum += ord(low)

    my_sum &= 0xffffffff
    my_sum = (my_sum >> 16) + (my_sum & 0xffff)
    my_sum += (my_sum >> 16)
    answer = ~my_sum & 0xffff

    return answer
