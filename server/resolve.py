# Converts between hostnames and IP addresses
# Currently only supports IPv4

import socket

def resolve_host(hostname):
    '''
        Resolves given hostnames to IPv4 addresses

        * hostname - hostname to be converted

        Returns an IPv4 address representing the given hostname. If
        the hostname is already an IPv4 address, the address itself
        is returned.
    '''

    try:
        ip = socket.gethostbyname(hostname)
    except:
        print('[-] Unable to resolve host: %s' % hostname)
        return None

    return ip
