# Manages bot data by creating and retrieving entries for other modules

import sys
import sqlite3

from defs import DB_PATH

def open_database(db_path):
    '''
        Attempts to connect to the database

        * db_path - path to database
    '''

    try:
        conn = sqlite3.connect(db_path)
        print('[+] Connected to database')
    except Exception:
        print('[-] Failed to connect to database')
        sys.exit(1)

    return conn

def create_bot_entry(data):
    '''
        Adds a new bot into the database

        * data - dictionary object representing bot credentials
    '''

    conn = open_database(DB_PATH)
    cur = conn.cursor()

    try:
        cur.execute(
            'INSERT INTO Bots VALUES (?, ?, ?, ?)',
            (
                data['addr'],
                data['port'],
                data['username'],
                data['password'],
            )
        )
        print(
            '''[+] Added bot(
        addr: %s
        port: %d
        username: %s
        password: %s
    )
            '''
            % (
                data['addr'],
                data['port'],
                data['username'],
                data['password']
            )
        )
        conn.commit()
    except Exception:
        print('[-] Failed to add bot entry!')

    conn.close()
